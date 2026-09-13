// Windows Hello consent plus a locked-memory session holder for vault
// wrapping keys, over C++/WinRT (ships in the Windows SDK, no extra dep).
//
// Threading, read before touching: every WinRT call runs on a libuv worker
// (Napi::AsyncWorker), never on Node's or Electron's main thread —
// init_apartment on a UI thread this process does not own (Electron's is
// STA) would either fail or, worse, succeed halfway. Workers get a fresh
// MTA apartment per call; the two APIs used here (CheckAvailability,
// RequestVerification) are brokered out-of-proc, so a blocking .get() on a
// worker is the documented console-app pattern, not a pump-less STA wait.
//
// What Hello is and is not here: requestConsent proves a human is present
// for this session (the OS prompt, not ours). It does NOT make DPAPI blobs
// unreadable to same-user malware — nothing short of a TPM-held key or a
// SYSTEM service does that, and this machine has neither verifiable. The
// passphrase provider (KPHR1) is the malware-resistant at-rest story; Hello
// (KHEL1) is presence-gating plus a lock-screen wipe. Both ride the session
// holder below, which keeps wrapping bytes in VirtualLock'd heap and wipes
// them on close — the most a user-mode process can do, stated plainly.
//
// Error contract: JavaScript receives only a generic failure. Consent resolves
// false on cancel or refusal, and neither HRESULTs nor credential details are
// ever exposed across this native boundary.
#include <napi.h>
#include <windows.h>
#include <wincred.h>

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>

namespace {

namespace consent = winrt::Windows::Security::Credentials::UI;

std::wstring Utf8ToWide(const std::string& s) {
  if (s.empty()) return L"";
  const int n =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
  if (n == 0) throw std::runtime_error("input is not valid UTF-8");
  std::wstring out(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
}

std::string WideToUtf8(const std::wstring& s) {
  if (s.empty()) return "";
  const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
  if (n == 0) throw std::runtime_error("wide-to-utf8 conversion failed");
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
  return out;
}

BYTE HexNibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<BYTE>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<BYTE>(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return static_cast<BYTE>(c - 'A' + 10);
  throw std::runtime_error("key is not hex");
}

std::vector<BYTE> HexToBytes(const std::string& hex) {
  if (hex.empty() || hex.size() % 2 != 0 || hex.size() > 8192) {
    throw std::runtime_error("key must be non-empty even-length hex, at most 4KiB");
  }
  std::vector<BYTE> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    out.push_back(static_cast<BYTE>((HexNibble(hex[i]) << 4) | HexNibble(hex[i + 1])));
  }
  return out;
}

std::string BytesToHex(const std::vector<BYTE>& bytes) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (BYTE b : bytes) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 0xF]);
  }
  return out;
}

// The session: wrapping bytes per account in VirtualLock'd heap. The lock is
// best-effort (working-set quota can refuse it) — held regardless, wiped on
// close regardless. Never paged in spirit; always wiped in fact.
struct SessionEntry {
  std::vector<BYTE> key;
};

std::map<std::wstring, SessionEntry> g_sessions;
std::mutex g_mutex;

std::vector<BYTE> CurrentUserSid() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw std::runtime_error("cannot query current user");
  DWORD needed = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
  std::vector<BYTE> out(needed);
  if (!GetTokenInformation(token, TokenUser, out.data(), needed, &needed)) {
    CloseHandle(token);
    throw std::runtime_error("cannot read current user");
  }
  CloseHandle(token);
  return out;
}

bool PasswordVerifiesCurrentUser(const std::string& reason) {
  CREDUI_INFOW ui{};
  const std::wstring text = Utf8ToWide(reason);
  ui.cbSize = sizeof(ui);
  ui.pszCaptionText = L"Plow Latch";
  ui.pszMessageText = text.c_str();
  ULONG package = 0;
  LPVOID packed = nullptr;
  ULONG packed_size = 0;
  BOOL save = FALSE;
  const DWORD prompt = CredUIPromptForWindowsCredentialsW(
      &ui, 0, &package, nullptr, 0, &packed, &packed_size, &save, CREDUIWIN_SECURE_PROMPT);
  if (prompt == ERROR_CANCELLED) return false;
  if (prompt != ERROR_SUCCESS) throw std::runtime_error("Windows credential prompt failed");
  std::vector<wchar_t> user(256), domain(256), password(256);
  DWORD user_len = static_cast<DWORD>(user.size());
  DWORD domain_len = static_cast<DWORD>(domain.size());
  DWORD password_len = static_cast<DWORD>(password.size());
  BOOL ok = CredUnPackAuthenticationBufferW(0, packed, packed_size, user.data(), &user_len,
                                             domain.data(), &domain_len, password.data(), &password_len);
  if (!ok && user_len > 0 && domain_len > 0 && password_len > 0 &&
      user_len <= 4096 && domain_len <= 4096 && password_len <= 4096) {
    // The first call is also the documented size probe. Wipe its partial
    // output BEFORE vector growth can move a credential buffer elsewhere.
    SecureZeroMemory(user.data(), user.size() * sizeof(wchar_t));
    SecureZeroMemory(domain.data(), domain.size() * sizeof(wchar_t));
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    user.assign(user_len, L'\0');
    domain.assign(domain_len, L'\0');
    password.assign(password_len, L'\0');
    user_len = static_cast<DWORD>(user.size());
    domain_len = static_cast<DWORD>(domain.size());
    password_len = static_cast<DWORD>(password.size());
    ok = CredUnPackAuthenticationBufferW(0, packed, packed_size, user.data(), &user_len,
                                          domain.data(), &domain_len, password.data(), &password_len);
  }
  SecureZeroMemory(packed, packed_size);
  CoTaskMemFree(packed);
  if (!ok) {
    SecureZeroMemory(user.data(), user.size() * sizeof(wchar_t));
    SecureZeroMemory(domain.data(), domain.size() * sizeof(wchar_t));
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    throw std::runtime_error("Windows credential verification failed");
  }
  HANDLE verified = nullptr;
  const wchar_t* domain_arg = domain[0] == L'\0' ? nullptr : domain.data();
  const BOOL logged_on = LogonUserW(user.data(), domain_arg, password.data(), LOGON32_LOGON_INTERACTIVE,
                                    LOGON32_PROVIDER_DEFAULT, &verified);
  SecureZeroMemory(user.data(), user.size() * sizeof(wchar_t));
  SecureZeroMemory(domain.data(), domain.size() * sizeof(wchar_t));
  SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
  if (!logged_on) return false;
  // `TOKEN_USER::User.Sid` is the mutable Win32 `PSID` typedef even when it
  // points at an immutable SID buffer.  Keep this owned copy non-const so the
  // comparison has the exact Win32 type without casting away constness (newer
  // MSVC correctly rejects that cast).
  std::vector<BYTE> current = CurrentUserSid();
  DWORD needed = 0;
  GetTokenInformation(verified, TokenUser, nullptr, 0, &needed);
  std::vector<BYTE> actual(needed);
  const bool same = GetTokenInformation(verified, TokenUser, actual.data(), needed, &needed) &&
                    EqualSid(reinterpret_cast<TOKEN_USER*>(current.data())->User.Sid,
                             reinterpret_cast<TOKEN_USER*>(actual.data())->User.Sid);
  CloseHandle(verified);
  SecureZeroMemory(actual.data(), actual.size());
  return same;
}

void WipeEntry(SessionEntry& entry) {
  if (!entry.key.empty()) {
    SecureZeroMemory(entry.key.data(), entry.key.size());
    VirtualUnlock(entry.key.data(), entry.key.size());
  }
  SessionEntry fresh;
  entry.key.swap(fresh.key);
}

class ConsentWorker : public Napi::AsyncWorker {
 public:
  ConsentWorker(Napi::Env env, std::string reason)
      : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), reason_(std::move(reason)) {}

  Napi::Promise Promise() { return deferred_.Promise(); }

 protected:
  void Execute() override {
    try {
      winrt::init_apartment();
    } catch (const winrt::hresult_error& e) {
      // RPC_E_CHANGED_MODE: this pool thread already has an apartment (not
      // ours). The brokered consent UX does not need ours; proceed.
      if (e.code() != 0x80010106) {
        SetError("Windows Hello verification failed");
        return;
      }
    }
    try {
      const auto result =
          consent::UserConsentVerifier::RequestVerificationAsync(Utf8ToWide(reason_).c_str()).get();
      consented_ = (result == consent::UserConsentVerificationResult::Verified);
    } catch (const winrt::hresult_error&) {
      SetError("Windows Hello verification failed");
    } catch (const std::exception&) {
      SetError("Windows Hello verification failed");
    }
  }

  void OnOK() override { deferred_.Resolve(Napi::Boolean::New(Env(), consented_)); }
  void OnError(const Napi::Error& error) override { deferred_.Reject(error.Value()); }

 private:
  Napi::Promise::Deferred deferred_;
  std::string reason_;
  bool consented_ = false;
};

class AvailabilityWorker : public Napi::AsyncWorker {
 public:
  AvailabilityWorker(Napi::Env env) : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)) {}

  Napi::Promise Promise() { return deferred_.Promise(); }

 protected:
  void Execute() override {
    try {
      winrt::init_apartment();
    } catch (const winrt::hresult_error& e) {
      if (e.code() != 0x80010106) {
        SetError("Windows Hello availability check failed");
        return;
      }
    }
    try {
      const auto status = consent::UserConsentVerifier::CheckAvailabilityAsync().get();
      switch (status) {
        case consent::UserConsentVerifierAvailability::Available:
          availability_ = "available";
          break;
        case consent::UserConsentVerifierAvailability::DeviceNotPresent:
          availability_ = "device-not-present";
          break;
        case consent::UserConsentVerifierAvailability::DisabledByPolicy:
          availability_ = "disabled-by-policy";
          break;
        default:
          availability_ = "unavailable";
          break;
      }
    } catch (const winrt::hresult_error&) {
      SetError("Windows Hello availability check failed");
    } catch (const std::exception&) {
      SetError("Windows Hello availability check failed");
    }
  }

  void OnOK() override { deferred_.Resolve(Napi::String::New(Env(), availability_)); }
  void OnError(const Napi::Error& error) override { deferred_.Reject(error.Value()); }

 private:
  Napi::Promise::Deferred deferred_;
  std::string availability_ = "unavailable";
};

class PasswordWorker : public Napi::AsyncWorker {
 public:
  PasswordWorker(Napi::Env env, std::string reason)
      : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)), reason_(std::move(reason)) {}
  Napi::Promise Promise() { return deferred_.Promise(); }
 protected:
  void Execute() override {
    try { verified_ = PasswordVerifiesCurrentUser(reason_); }
    catch (const std::exception&) { SetError("Windows credential verification failed"); }
  }
  void OnOK() override { deferred_.Resolve(Napi::Boolean::New(Env(), verified_)); }
  void OnError(const Napi::Error& error) override { deferred_.Reject(error.Value()); }
 private:
  Napi::Promise::Deferred deferred_;
  std::string reason_;
  bool verified_ = false;
};

// checkAvailability() -> Promise<string>
Napi::Value CheckAvailability(const Napi::CallbackInfo& info) {
  auto* worker = new AvailabilityWorker(info.Env());
  worker->Queue();
  return worker->Promise();
}

// requestConsent(reason) -> Promise<boolean>
Napi::Value RequestConsent(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  std::string reason;
  try {
    reason = info[0].As<Napi::String>().Utf8Value();
  } catch (...) {
    throw Napi::Error::New(env, "reason must be a string");
  }
  auto* worker = new ConsentWorker(env, std::move(reason));
  worker->Queue();
  return worker->Promise();
}

// requestPassword(reason) -> Promise<boolean>. The native implementation
// authenticates the current Windows SID on the secure desktop and destroys
// every credential buffer before resolving only the boolean.
Napi::Value RequestPassword(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  std::string reason;
  try { reason = info[0].As<Napi::String>().Utf8Value(); }
  catch (...) { throw Napi::Error::New(env, "reason must be a string"); }
  auto* worker = new PasswordWorker(env, std::move(reason));
  worker->Queue();
  return worker->Promise();
}

// sessionHold(account, keyHex) -> undefined. Replaces any existing session.
Napi::Value SessionHold(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  std::wstring account;
  std::vector<BYTE> key;
  try {
    account = Utf8ToWide(info[0].As<Napi::String>().Utf8Value());
    key = HexToBytes(info[1].As<Napi::String>().Utf8Value());
  } catch (const std::exception& e) {
    throw Napi::Error::New(env, e.what());
  }
  std::lock_guard<std::mutex> lock(g_mutex);
  auto& entry = g_sessions[account];
  WipeEntry(entry);
  entry.key = std::move(key);
  // Best-effort page lock; the wipe below is the guarantee, this is the hope.
  VirtualLock(entry.key.data(), entry.key.size());
  return env.Undefined();
}

// sessionGet(account) -> string | null. A fresh hex copy per call.
Napi::Value SessionGet(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  std::wstring account;
  try {
    account = Utf8ToWide(info[0].As<Napi::String>().Utf8Value());
  } catch (const std::exception& e) {
    throw Napi::Error::New(env, e.what());
  }
  std::lock_guard<std::mutex> lock(g_mutex);
  const auto it = g_sessions.find(account);
  if (it == g_sessions.end() || it->second.key.empty()) return env.Null();
  return Napi::String::New(env, BytesToHex(it->second.key));
}

// sessionClose(account) -> undefined. Wipe, unlock, forget. Idempotent: a
// missing session is not an error — the lock-screen path must never fail.
Napi::Value SessionClose(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  std::wstring account;
  try {
    account = Utf8ToWide(info[0].As<Napi::String>().Utf8Value());
  } catch (const std::exception& e) {
    throw Napi::Error::New(env, e.what());
  }
  std::lock_guard<std::mutex> lock(g_mutex);
  const auto it = g_sessions.find(account);
  if (it != g_sessions.end()) {
    WipeEntry(it->second);
    g_sessions.erase(it);
  }
  return env.Undefined();
}

// sessionCloseAll() -> undefined.
Napi::Value SessionCloseAll(const Napi::CallbackInfo& info) {
  std::lock_guard<std::mutex> lock(g_mutex);
  for (auto& [account, entry] : g_sessions) WipeEntry(entry);
  g_sessions.clear();
  return info.Env().Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("checkAvailability", Napi::Function::New(env, CheckAvailability));
  exports.Set("requestConsent", Napi::Function::New(env, RequestConsent));
  exports.Set("requestPassword", Napi::Function::New(env, RequestPassword));
  exports.Set("sessionHold", Napi::Function::New(env, SessionHold));
  exports.Set("sessionGet", Napi::Function::New(env, SessionGet));
  exports.Set("sessionClose", Napi::Function::New(env, SessionClose));
  exports.Set("sessionCloseAll", Napi::Function::New(env, SessionCloseAll));
  return exports;
}

NODE_API_MODULE(winhello, Init)

}  // namespace
