// Windows secret-file ACL lockdown, through SetNamedSecurityInfo.
//
// What chmod 0600 cannot do on NTFS: it is advisory there, so a secret file
// inherits its parent's DACL (SYSTEM, Administrators, and whoever else the
// profile grants). lockdownFile replaces the DACL with a single owner-only
// ACE and marks it protected (no inheritance) — the file analogue of what
// Credential Manager gives the vault key by default.
//
// The grant is GENERIC_READ | GENERIC_WRITE | DELETE for the current user:
// read+append for logs, and DELETE because every secret writer here replaces
// by rename, which needs delete rights on the destination. The owner is left
// alone; only the DACL is replaced. Idempotent: a second lockdown writes the
// same single ACE.
//
// What it is NOT: protection against Administrators (they can take ownership
// of anything) or against the same user's other processes reading the file
// handle — that is DPAPI/Credential Manager's job for the secrets themselves.
// This closes the disk-theft and multi-user-readable-profile holes, nothing more.
//
// Error contract: failures throw an Error whose `code` property is the Win32
// error. Mirrors wincred.cc.
#include <napi.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <string>
#include <vector>

namespace {

Napi::Error WinError(Napi::Env env, DWORD code, const char* what) {
  Napi::Error err =
      Napi::Error::New(env, std::string(what) + " failed (Win32 " + std::to_string(code) + ")");
  err.Set("code", Napi::Number::New(env, code));
  return err;
}

// UTF-8 (JS, and paths under usernames with accents) to UTF-16. wincred.cc
// gets away with a byte copy because its inputs are ASCII service names;
// file paths are not.
std::wstring Utf8ToWide(const std::string& s) {
  if (s.empty()) return L"";
  const int n =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
  if (n == 0) throw std::runtime_error("path is not valid UTF-8");
  std::wstring out(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
}

std::string WideToUtf8(const wchar_t* s) {
  if (s == nullptr || *s == L'\0') return "";
  const int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
  if (n == 0) throw std::runtime_error("wide-to-utf8 conversion failed");
  std::string out(static_cast<size_t>(n - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr);
  return out;
}

// The current user's SID, binary (for the ACE) and string (for the caller).
// One token query serves both so they cannot disagree.
struct CurrentUser {
  std::vector<BYTE> sid;
  std::string sidString;
};

CurrentUser GetCurrentUser() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    throw std::runtime_error("OpenProcessToken failed (" + std::to_string(GetLastError()) + ")");
  }
  DWORD needed = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
  std::vector<BYTE> buf(needed);
  if (!GetTokenInformation(token, TokenUser, buf.data(), needed, &needed)) {
    const DWORD code = GetLastError();
    CloseHandle(token);
    throw std::runtime_error("GetTokenInformation failed (" + std::to_string(code) + ")");
  }
  auto* user = reinterpret_cast<TOKEN_USER*>(buf.data());
  const DWORD sidLen = GetLengthSid(user->User.Sid);
  LPWSTR str = nullptr;
  if (!ConvertSidToStringSidW(user->User.Sid, &str)) {
    const DWORD code = GetLastError();
    CloseHandle(token);
    throw std::runtime_error("ConvertSidToStringSidW failed (" + std::to_string(code) + ")");
  }
  std::string sidString;
  try {
    sidString = WideToUtf8(str);
  } catch (...) {
    LocalFree(str);
    CloseHandle(token);
    throw;
  }
  LocalFree(str);
  std::vector<BYTE> sid(sidLen);
  if (!CopySid(sidLen, sid.data(), user->User.Sid)) {
    const DWORD code = GetLastError();
    CloseHandle(token);
    throw std::runtime_error("CopySid failed (" + std::to_string(code) + ")");
  }
  CloseHandle(token);
  return {std::move(sid), std::move(sidString)};
}

// lockdownFile(path) -> string (the SID now exclusively granted)
Napi::Value LockdownFile(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  std::wstring path;
  try {
    path = Utf8ToWide(info[0].As<Napi::String>().Utf8Value());
  } catch (const std::exception& e) {
    throw Napi::Error::New(env, e.what());
  }
  CurrentUser user;
  try {
    user = GetCurrentUser();
  } catch (const std::exception& e) {
    throw Napi::Error::New(env, e.what());
  }
  EXPLICIT_ACCESSW ea{};
  ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | DELETE;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance = NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
  ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(user.sid.data());
  PACL acl = nullptr;
  if (SetEntriesInAclW(1, &ea, nullptr, &acl) != ERROR_SUCCESS) {
    throw WinError(env, GetLastError(), "SetEntriesInAclW");
  }
  const DWORD code = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                           DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                           nullptr, nullptr, acl, nullptr);
  LocalFree(acl);
  if (code != ERROR_SUCCESS) {
    throw WinError(env, code, "SetNamedSecurityInfoW");
  }
  return Napi::String::New(env, user.sidString);
}

// readFileSddl(path) -> string (SDDL of owner+group+DACL, for tests)
Napi::Value ReadFileSddl(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  std::wstring path;
  try {
    path = Utf8ToWide(info[0].As<Napi::String>().Utf8Value());
  } catch (const std::exception& e) {
    throw Napi::Error::New(env, e.what());
  }
  PSECURITY_DESCRIPTOR sd = nullptr;
  const DWORD code = GetNamedSecurityInfoW(
      const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr,
      nullptr, nullptr, &sd);
  if (code != ERROR_SUCCESS) {
    throw WinError(env, code, "GetNamedSecurityInfoW");
  }
  LPWSTR out = nullptr;
  std::string sddl;
  try {
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd, SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &out,
            nullptr)) {
      throw WinError(env, GetLastError(), "ConvertSecurityDescriptorToStringSecurityDescriptorW");
    }
    sddl = WideToUtf8(out);
  } catch (...) {
    if (out != nullptr) LocalFree(out);
    LocalFree(sd);
    throw;
  }
  LocalFree(out);
  LocalFree(sd);
  return Napi::String::New(env, sddl);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("lockdownFile", Napi::Function::New(env, LockdownFile));
  exports.Set("readFileSddl", Napi::Function::New(env, ReadFileSddl));
  return exports;
}

NODE_API_MODULE(winfs, Init)

}  // namespace
