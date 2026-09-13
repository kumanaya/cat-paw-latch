// Private AppContainer launcher for one Plow Latch command run.
//
// The launcher deliberately exposes no direct argv interface.  The only
// public action presently is --probe; the TypeScript side writes the private
// config protocol before this process is allowed to start a child.
#include <windows.h>
#include <userenv.h>
#include <aclapi.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr DWORD kActiveProcessLimit = 256;

struct LaunchConfig {
  bool network = false;
  std::string workspace;
  std::string cwd;
  std::string application;
  std::vector<std::string> args;
  // Trusted, package-owned binaries/modules which the confined process may
  // read and execute.  Agent capability paths never enter this list.
  std::vector<std::string> runtime_roots;
  std::map<std::string, std::string> env;
};

bool DecodeBase64(const std::string& text, std::string* output) {
  static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  if (text.empty() || text.size() % 4 != 0) return false;
  output->clear();
  for (size_t offset = 0; offset < text.size(); offset += 4) {
    int value[4]{};
    int padding = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = text[offset + i];
      if (c == '=') {
        // Padding is either one final '=' or the final pair '=='.
        if (i < 2 || (i == 2 && text[offset + 3] != '=')) return false;
        ++padding;
      } else {
        const size_t index = alphabet.find(c);
        if (index == std::string::npos || padding != 0) return false;
        value[i] = static_cast<int>(index);
      }
    }
    if (padding != 0 && offset + 4 != text.size()) return false;
    const unsigned packed = (value[0] << 18) | (value[1] << 12) | (value[2] << 6) | value[3];
    output->push_back(static_cast<char>((packed >> 16) & 0xff));
    if (padding < 2) output->push_back(static_cast<char>((packed >> 8) & 0xff));
    if (padding == 0) output->push_back(static_cast<char>(packed & 0xff));
  }
  return true;
}

bool SafeValue(const std::string& value) {
  return !value.empty() && value.find('\0') == std::string::npos && value.find('\r') == std::string::npos &&
         value.find('\n') == std::string::npos;
}

bool SafeEnvName(const std::string& name) {
  if (name.empty() || !(std::isalpha(static_cast<unsigned char>(name[0])) || name[0] == '_')) return false;
  return std::all_of(name.begin() + 1, name.end(), [](unsigned char c) { return std::isalnum(c) || c == '_'; });
}

bool ReadConfig(const wchar_t* filename, LaunchConfig* config) {
  std::ifstream file(filename, std::ios::binary);
  if (!file) return false;
  std::string line;
  if (!std::getline(file, line) || line != "PLOW-LATCH-APPCONTAINER-1") return false;
  bool network = false, workspace = false, cwd = false, application = false;
  while (std::getline(file, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    const size_t first = line.find(' ');
    if (first == std::string::npos) return false;
    const std::string label = line.substr(0, first);
    const std::string rest = line.substr(first + 1);
    std::string value;
    if (label == "network") {
      if (network || (rest != "0" && rest != "1")) return false;
      config->network = rest == "1";
      network = true;
    } else if (label == "workspace" || label == "cwd" || label == "application" || label == "arg" || label == "runtime") {
      if (!DecodeBase64(rest, &value) || !SafeValue(value)) return false;
      if (label == "workspace") { if (workspace) return false; config->workspace = value; workspace = true; }
      else if (label == "cwd") { if (cwd) return false; config->cwd = value; cwd = true; }
      else if (label == "application") { if (application) return false; config->application = value; application = true; }
      else config->args.push_back(value);
      if (label == "runtime") {
        if (std::find(config->runtime_roots.begin(), config->runtime_roots.end(), value) != config->runtime_roots.end()) return false;
        config->runtime_roots.push_back(value);
      }
    } else if (label == "env") {
      const size_t second = rest.find(' ');
      std::string key;
      if (second == std::string::npos || !DecodeBase64(rest.substr(0, second), &key) ||
          !DecodeBase64(rest.substr(second + 1), &value) || !SafeEnvName(key) || !SafeValue(value) ||
          config->env.contains(key)) return false;
      config->env.emplace(std::move(key), std::move(value));
    } else return false;
  }
  return network && workspace && cwd && application;
}

bool AddAppContainerAce(const std::wstring& target, PSID app_container_sid, DWORD permissions) {
  PACL old_acl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetNamedSecurityInfoW(const_cast<LPWSTR>(target.c_str()), SE_FILE_OBJECT,
                            DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_acl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  EXPLICIT_ACCESSW grant{};
  grant.grfAccessPermissions = permissions;
  grant.grfAccessMode = GRANT_ACCESS;
  grant.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  grant.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  grant.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  grant.Trustee.ptstrName = static_cast<LPWSTR>(app_container_sid);
  PACL merged = nullptr;
  const DWORD merged_status = SetEntriesInAclW(1, &grant, old_acl, &merged);
  const DWORD result = merged_status == ERROR_SUCCESS
      ? SetNamedSecurityInfoW(const_cast<LPWSTR>(target.c_str()), SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION, nullptr, nullptr, merged, nullptr)
      : merged_status;
  if (merged != nullptr) LocalFree(merged);
  LocalFree(descriptor);
  return result == ERROR_SUCCESS;
}

bool AddWorkspaceAce(const std::wstring& workspace, PSID app_container_sid) {
  return AddAppContainerAce(workspace, app_container_sid, GENERIC_ALL);
}

bool AddRuntimeAce(const std::wstring& runtime, PSID app_container_sid) {
  return AddAppContainerAce(runtime, app_container_sid, GENERIC_READ | GENERIC_EXECUTE);
}

bool CreateThenDeleteProfile() {
  const std::wstring name = L"PlowLatch.LauncherProbe." + std::to_wstring(GetCurrentProcessId()) +
                            L"." + std::to_wstring(GetTickCount64());
  PSID sid = nullptr;
  const HRESULT created = CreateAppContainerProfile(name.c_str(), name.c_str(), L"Plow Latch launcher probe", nullptr, 0, &sid);
  if (FAILED(created)) return false;
  FreeSid(sid);
  return SUCCEEDED(DeleteAppContainerProfile(name.c_str()));
}

// This invariant is kept native because no Node process may place a child in
// an AppContainer after it starts.  Its config-backed call site is introduced
// only with the complete parser, output proxy and workspace protocol.
bool CanCreateAppContainerForWorkspace(const std::wstring& workspace) {
  const std::wstring name = L"PlowLatch.WorkspaceProbe." + std::to_wstring(GetCurrentProcessId()) +
                            L"." + std::to_wstring(GetTickCount64());
  PSID sid = nullptr;
  const HRESULT created = CreateAppContainerProfile(name.c_str(), name.c_str(), L"Plow Latch workspace probe", nullptr, 0, &sid);
  if (FAILED(created)) return false;
  const bool granted = AddWorkspaceAce(workspace, sid);
  FreeSid(sid);
  DeleteAppContainerProfile(name.c_str());
  return granted;
}

std::wstring Wide(const std::string& value) {
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (size == 0) return L"";
  std::wstring result(static_cast<size_t>(size), L'\0');
  return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size) == size
      ? result : L"";
}

std::wstring QuoteArg(const std::wstring& value) {
  std::wstring result = L"\"";
  size_t slashes = 0;
  for (wchar_t c : value) {
    if (c == L'\\') { ++slashes; continue; }
    result.append(slashes * (c == L'\"' ? 2 : 1) + (c == L'\"' ? 1 : 0), L'\\');
    slashes = 0;
    result.push_back(c);
  }
  result.append(slashes * 2, L'\\');
  result.push_back(L'\"');
  return result;
}

bool InternetCapability(PSID* output) {
  PSID* groups = nullptr;
  DWORD group_count = 0;
  PSID* capabilities = nullptr;
  DWORD capability_count = 0;
  const bool ok = DeriveCapabilitySidsFromName(L"internetClient", &groups, &group_count,
                                               &capabilities, &capability_count) && capability_count == 1;
  if (groups != nullptr) {
    for (DWORD i = 0; i < group_count; ++i) LocalFree(groups[i]);
    LocalFree(groups);
  }
  if (!ok) { if (capabilities != nullptr) LocalFree(capabilities); return false; }
  *output = capabilities[0];
  LocalFree(capabilities);
  return true;
}

void ForwardPipe(HANDLE input, HANDLE output) {
  char buffer[4096];
  DWORD read = 0, written = 0;
  while (ReadFile(input, buffer, sizeof(buffer), &read, nullptr) && read != 0) {
    WriteFile(output, buffer, read, &written, nullptr);
  }
  CloseHandle(input);
}

int LaunchAppContainer(const LaunchConfig& config) {
  const std::wstring workspace = Wide(config.workspace);
  const std::wstring cwd = Wide(config.cwd);
  const std::wstring application = Wide(config.application);
  if (workspace.empty() || cwd.empty() || application.empty()) return 70;
  const std::wstring profile_name = L"PlowLatch.Run." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64());
  PSID app_sid = nullptr;
  if (FAILED(CreateAppContainerProfile(profile_name.c_str(), profile_name.c_str(), L"Plow Latch command", nullptr, 0, &app_sid))) return 71;
  PSID network_sid = nullptr;
  bool runtime_granted = true;
  for (const std::string& root : config.runtime_roots) {
    const std::wstring runtime = Wide(root);
    if (runtime.empty() || !AddRuntimeAce(runtime, app_sid)) { runtime_granted = false; break; }
  }
  if ((config.network && !InternetCapability(&network_sid)) || !AddWorkspaceAce(workspace, app_sid) || !runtime_granted) {
    if (network_sid != nullptr) LocalFree(network_sid);
    FreeSid(app_sid);
    DeleteAppContainerProfile(profile_name.c_str());
    return 72;
  }
  SID_AND_ATTRIBUTES capability{};
  capability.Sid = network_sid;
  capability.Attributes = SE_GROUP_ENABLED;
  SECURITY_CAPABILITIES security{};
  security.AppContainerSid = app_sid;
  security.Capabilities = config.network ? &capability : nullptr;
  security.CapabilityCount = config.network ? 1 : 0;

  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  auto* attributes = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, size));
  if (attributes == nullptr || !InitializeProcThreadAttributeList(attributes, 1, 0, &size) ||
      !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security, sizeof(security), nullptr, nullptr)) {
    if (attributes != nullptr) HeapFree(GetProcessHeap(), 0, attributes);
    if (network_sid != nullptr) LocalFree(network_sid);
    FreeSid(app_sid);
    DeleteAppContainerProfile(profile_name.c_str());
    return 73;
  }

  std::vector<std::pair<std::wstring, std::wstring>> environment_entries;
  for (const auto& [key, value] : config.env) {
    const std::wstring wide_key = Wide(key), wide_value = Wide(value);
    if (wide_key.empty() || wide_value.empty()) {
      DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(), 0, attributes);
      if (network_sid != nullptr) LocalFree(network_sid); FreeSid(app_sid); DeleteAppContainerProfile(profile_name.c_str());
      return 74;
    }
    environment_entries.emplace_back(wide_key, wide_value);
  }
  std::sort(environment_entries.begin(), environment_entries.end(), [](const auto& left, const auto& right) {
    return _wcsicmp(left.first.c_str(), right.first.c_str()) < 0;
  });
  std::wstring environment;
  for (const auto& [key, value] : environment_entries) environment += key + L"=" + value + L'\0';
  environment += L'\0';
  std::wstring command_line = QuoteArg(application);
  for (const std::string& arg : config.args) {
    const std::wstring wide_arg = Wide(arg);
    if (wide_arg.empty()) { DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(), 0, attributes);
      if (network_sid != nullptr) LocalFree(network_sid); FreeSid(app_sid); DeleteAppContainerProfile(profile_name.c_str()); return 74; }
    command_line += L" " + QuoteArg(wide_arg);
  }
  std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back(L'\0');
  SECURITY_ATTRIBUTES inheritable{};
  inheritable.nLength = sizeof(inheritable);
  inheritable.bInheritHandle = TRUE;
  HANDLE stdout_read = nullptr, stdout_write = nullptr, stderr_read = nullptr, stderr_write = nullptr;
  HANDLE null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (null_input == INVALID_HANDLE_VALUE || !CreatePipe(&stdout_read, &stdout_write, &inheritable, 0) ||
      !CreatePipe(&stderr_read, &stderr_write, &inheritable, 0) ||
      !SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0) || !SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0)) {
    if (null_input != INVALID_HANDLE_VALUE) CloseHandle(null_input);
    if (stdout_read != nullptr) CloseHandle(stdout_read); if (stdout_write != nullptr) CloseHandle(stdout_write);
    if (stderr_read != nullptr) CloseHandle(stderr_read); if (stderr_write != nullptr) CloseHandle(stderr_write);
    DeleteProcThreadAttributeList(attributes); HeapFree(GetProcessHeap(), 0, attributes);
    if (network_sid != nullptr) LocalFree(network_sid); FreeSid(app_sid); DeleteAppContainerProfile(profile_name.c_str()); return 75;
  }
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = null_input;
  startup.StartupInfo.hStdOutput = stdout_write;
  startup.StartupInfo.hStdError = stderr_write;
  startup.lpAttributeList = attributes;
  PROCESS_INFORMATION process{};
  const BOOL created = CreateProcessW(application.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
                                      EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                                      environment.data(), cwd.c_str(), &startup.StartupInfo, &process);
  DeleteProcThreadAttributeList(attributes);
  HeapFree(GetProcessHeap(), 0, attributes);
  CloseHandle(null_input); CloseHandle(stdout_write); CloseHandle(stderr_write);
  if (!created) {
    CloseHandle(stdout_read); CloseHandle(stderr_read);
    if (network_sid != nullptr) LocalFree(network_sid); FreeSid(app_sid); DeleteAppContainerProfile(profile_name.c_str()); return 75;
  }

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  limits.BasicLimitInformation.ActiveProcessLimit = kActiveProcessLimit;
  if (job == nullptr || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
      !AssignProcessToJobObject(job, process.hProcess) || ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
    if (job != nullptr) CloseHandle(job);
    TerminateProcess(process.hProcess, ERROR_ACCESS_DENIED);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    CloseHandle(stdout_read); CloseHandle(stderr_read);
    if (network_sid != nullptr) LocalFree(network_sid); FreeSid(app_sid); DeleteAppContainerProfile(profile_name.c_str()); return 76;
  }
  std::thread stdout_proxy(ForwardPipe, stdout_read, GetStdHandle(STD_OUTPUT_HANDLE));
  std::thread stderr_proxy(ForwardPipe, stderr_read, GetStdHandle(STD_ERROR_HANDLE));
  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD exit_code = 1;
  GetExitCodeProcess(process.hProcess, &exit_code);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  stdout_proxy.join();
  stderr_proxy.join();
  CloseHandle(job);  // after the child ended; descendants die here if any remain.
  if (network_sid != nullptr) LocalFree(network_sid);
  FreeSid(app_sid);
  DeleteAppContainerProfile(profile_name.c_str());
  return static_cast<int>(exit_code);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && std::wstring(argv[1]) == L"--probe") return CreateThenDeleteProfile() ? 0 : 1;
  if (argc == 3 && std::wstring(argv[1]) == L"--config") {
    LaunchConfig config;
    if (!ReadConfig(argv[2], &config)) return 65;
    // A provider token exists in the config only until this point.
    DeleteFileW(argv[2]);
    return LaunchAppContainer(config);
  }
  return 64;  // EX_USAGE: fail closed for every unimplemented interface.
}
