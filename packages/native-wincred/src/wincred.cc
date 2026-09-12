// One generic credential in the Windows Credential Manager, through
// CredRead/CredWrite — the API surface Electron's safeStorage cannot reach
// with a caller-chosen target name. Three functions, no state, no policy:
// which service/account to use is the caller's decision (and a frozen
// constant in @domo/device-core, for the reasons its comment gives).
// Read, write, probe — no delete: destroying a vault key is not an operation
// anything owns, so the boundary does not offer it.
//
// The credential target is "<service>/<account>" — a free-form generic-credential
// name under CRED_TYPE_GENERIC, persisted per machine (CRED_PERSIST_LOCAL_MACHINE).
// The blob is the caller's UTF-8 (the vault master key as hex); it is well under
// CRED_MAX_CREDENTIAL_BLOB_SIZE.
//
// Error contract: a missing item is `null`, never a throw. Everything else
// throws an Error whose `code` property is the Win32 error, so the caller can
// tell "no usable logon session" (ERROR_NO_SUCH_LOGON_SESSION) from real
// failures and fall back to another provider. Mirrors keychain.mm.
#include <napi.h>
#include <windows.h>
#include <wincred.h>

#include <string>
#include <vector>

namespace {

// Target naming: one namespace, caller-chosen leaves. The separator keeps a
// service from colliding with an account that contains a slash the other way
// round — both halves are ours and neither contains one, but the shape is
// what a reader of Credential Manager sees, so it stays explicit.
std::wstring TargetName(const std::string& service, const std::string& account) {
  std::string joined = service + "/" + account;
  return std::wstring(joined.begin(), joined.end());
}

std::wstring ToWString(const Napi::Value& v) {
  const std::string s = v.As<Napi::String>().Utf8Value();
  return std::wstring(s.begin(), s.end());
}

std::string ToString(const Napi::Value& v) { return v.As<Napi::String>().Utf8Value(); }

Napi::Error WinError(Napi::Env env, DWORD code, const char* what) {
  Napi::Error err =
      Napi::Error::New(env, std::string(what) + " failed (Win32 " + std::to_string(code) + ")");
  err.Set("code", Napi::Number::New(env, code));
  return err;
}

// get(service, account) -> string | null
Napi::Value Get(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  const std::wstring target = TargetName(ToString(info[0]), ToString(info[1]));
  PCREDENTIALW cred = nullptr;
  if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
    const DWORD code = GetLastError();
    if (code == ERROR_NOT_FOUND) return env.Null();
    throw WinError(env, code, "CredReadW");
  }
  std::string out(reinterpret_cast<char*>(cred->CredentialBlob), cred->CredentialBlobSize);
  CredFree(cred);
  return Napi::String::New(env, out);
}

// set(service, account, value) -> undefined. Upserts: CredWrite overwrites a
// credential with the same target, so there is no add/update split.
Napi::Value Set(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  const std::wstring target = TargetName(ToString(info[0]), ToString(info[1]));
  const std::string value = ToString(info[2]);
  CREDENTIALW cred{};
  cred.Flags = 0;
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = const_cast<LPWSTR>(target.c_str());
  cred.CredentialBlobSize = static_cast<DWORD>(value.size());
  cred.CredentialBlob =
      reinterpret_cast<LPBYTE>(const_cast<char*>(value.data()));
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
  if (!CredWriteW(&cred, 0)) {
    throw WinError(env, GetLastError(), "CredWriteW");
  }
  return env.Undefined();
}

// probe(service) -> "ok" | "unavailable"
// A read that expects to find nothing: ERROR_NOT_FOUND proves Credential
// Manager answered for this session, which is all availability means.
// Anything else (no logon session, locked store) is "unavailable", and the
// caller falls back to safeStorage or the key file.
Napi::Value Probe(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  const std::wstring target = TargetName(ToString(info[0]), "__probe__");
  PCREDENTIALW cred = nullptr;
  if (CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
    CredFree(cred);
    return Napi::String::New(env, "ok");
  }
  const DWORD code = GetLastError();
  if (code == ERROR_NOT_FOUND) return Napi::String::New(env, "ok");
  return Napi::String::New(env, "unavailable");
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("get", Napi::Function::New(env, Get));
  exports.Set("set", Napi::Function::New(env, Set));
  exports.Set("probe", Napi::Function::New(env, Probe));
  return exports;
}

NODE_API_MODULE(wincred, Init)

}  // namespace
