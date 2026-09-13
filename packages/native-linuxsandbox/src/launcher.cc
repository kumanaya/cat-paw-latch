// Private bubblewrap + cgroup v2 launcher for one Plow Latch command run.
//
// The launcher deliberately exposes no direct argv interface. The only public
// action is --probe; the TypeScript side writes the private config protocol
// before this process is allowed to start a child.
//
// Process cap: systemd-run --user --scope -p TasksMax=256 (cgroup v2 via the
// user's systemd). Direct mkdir+move into an arbitrary cgroup fails on many
// desktop sessions (session scopes cannot migrate into user@.service), so the
// systemd path is the reliable Job-Object equivalent.
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

namespace {

constexpr const char* kPidsMax = "256";
constexpr const char* kMagic = "PLOW-LATCH-BWRAP-1";

struct LaunchConfig {
  bool network = false;
  std::string workspace;
  std::string cwd;
  std::string application;
  std::vector<std::string> args;
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

bool ReadConfig(const char* filename, LaunchConfig* config) {
  std::ifstream file(filename, std::ios::binary);
  if (!file) return false;
  std::string line;
  if (!std::getline(file, line) || line != kMagic) return false;
  bool network = false, workspace = false, cwd = false, application = false;
  while (std::getline(file, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    const size_t first = line.find(' ');
    if (first == std::string::npos) return false;
    const std::string label = line.substr(0, first);
    const std::string rest = line.substr(first + 1);
    std::string value;
    if (label == "network") {
      if (network || (rest != "0" && rest != "1")) return false;
      config->network = rest == "1";
      network = true;
    } else if (label == "workspace" || label == "cwd" || label == "application" || label == "arg") {
      if (!DecodeBase64(rest, &value) || !SafeValue(value)) return false;
      if (label == "workspace") { if (workspace) return false; config->workspace = value; workspace = true; }
      else if (label == "cwd") { if (cwd) return false; config->cwd = value; cwd = true; }
      else if (label == "application") { if (application) return false; config->application = value; application = true; }
      else config->args.push_back(value);
    } else if (label == "env") {
      const size_t second = rest.find(' ');
      std::string key;
      if (second == std::string::npos || !DecodeBase64(rest.substr(0, second), &key) ||
          !DecodeBase64(rest.substr(second + 1), &value) || !SafeEnvName(key) || !SafeValue(value) ||
          config->env.find(key) != config->env.end()) return false;
      config->env.emplace(std::move(key), std::move(value));
    } else return false;
  }
  return network && workspace && cwd && application;
}

bool FileExecutable(const char* path) {
  struct stat st {};
  return ::stat(path, &st) == 0 && S_ISREG(st.st_mode) && ::access(path, X_OK) == 0;
}

bool PathExists(const char* path) {
  struct stat st {};
  return ::stat(path, &st) == 0;
}

std::string FindOnPath(const char* name) {
  const std::string absolute_candidates[] = {
      std::string("/usr/bin/") + name,
      std::string("/bin/") + name,
  };
  for (const auto& candidate : absolute_candidates) {
    if (FileExecutable(candidate.c_str())) return candidate;
  }
  const char* path = std::getenv("PATH");
  if (path == nullptr) return "";
  std::string remaining = path;
  while (!remaining.empty()) {
    const size_t sep = remaining.find(':');
    const std::string dir = sep == std::string::npos ? remaining : remaining.substr(0, sep);
    remaining = sep == std::string::npos ? "" : remaining.substr(sep + 1);
    if (dir.empty()) continue;
    const std::string candidate = dir + "/" + name;
    if (FileExecutable(candidate.c_str())) return candidate;
  }
  return "";
}

std::string FindBwrap() { return FindOnPath("bwrap"); }
std::string FindSystemdRun() { return FindOnPath("systemd-run"); }

int WaitStatus(int status) {
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 1;
}

int RunArgv(const std::vector<std::string>& storage, char* const envp[]) {
  std::vector<char*> argv;
  argv.reserve(storage.size() + 1);
  for (const auto& value : storage) argv.push_back(const_cast<char*>(value.data()));
  argv.push_back(nullptr);
  const pid_t child = ::fork();
  if (child < 0) return 75;
  if (child == 0) {
    const int null_fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd >= 0) {
      ::dup2(null_fd, STDIN_FILENO);
      ::close(null_fd);
    }
    ::execve(argv[0], argv.data(), envp);
    _exit(127);
  }
  int status = 1;
  if (::waitpid(child, &status, 0) < 0) return 75;
  return WaitStatus(status);
}

void RoBindTry(std::vector<std::string>* storage, const char* path) {
  if (!PathExists(path)) return;
  storage->push_back("--ro-bind");
  storage->push_back(path);
  storage->push_back(path);
}

void AppendSystemBinds(std::vector<std::string>* storage, bool network, const std::string& workspace) {
  auto push = [&](const std::string& value) { storage->push_back(value); };
  // Libraries and the dynamic linker ONLY — never /usr/bin or /bin as live
  // binds. Host executables must be staged into the workspace; binding all of
  // /usr would let a staged script exec an unapproved host tool.
  RoBindTry(storage, "/usr/lib");
  RoBindTry(storage, "/usr/lib64");
  RoBindTry(storage, "/lib");
  RoBindTry(storage, "/lib64");
  // Arch and other merged-/usr distros: /lib is a symlink to usr/lib on the
  // host. When /lib is missing as a real dir inside the sandbox, recreate the
  // usual layout with symlinks after binding /usr/lib.
  if (PathExists("/usr/lib") && !PathExists("/lib")) {
    push("--symlink");
    push("usr/lib");
    push("/lib");
  }
  if (PathExists("/usr/lib") && !PathExists("/lib64")) {
    push("--symlink");
    push("usr/lib");
    push("/lib64");
  }
  for (const char* etc : {"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/nsswitch.conf",
                          "/etc/passwd", "/etc/group", "/etc/localtime"}) {
    RoBindTry(storage, etc);
  }
  if (PathExists("/etc/ld.so.conf.d")) {
    push("--ro-bind");
    push("/etc/ld.so.conf.d");
    push("/etc/ld.so.conf.d");
  }
  if (network) RoBindTry(storage, "/etc/resolv.conf");
  push("--dev");
  push("/dev");
  push("--proc");
  push("/proc");
  // Drop ambient capabilities inside the sandbox.
  push("--cap-drop");
  push("ALL");
  push("--new-session");
  // Never tmpfs-over /tmp when the staged workspace lives under it — that
  // would hide the bind we just created. TMPDIR is set to the workspace.
  const bool workspace_under_tmp =
      workspace == "/tmp" || workspace.rfind("/tmp/", 0) == 0;
  if (!workspace_under_tmp) {
    push("--tmpfs");
    push("/tmp");
  }
}

bool ProbeOnce() {
  const std::string bwrap = FindBwrap();
  const std::string systemd_run = FindSystemdRun();
  if (bwrap.empty() || systemd_run.empty()) return false;
  const char* true_path = PathExists("/usr/bin/true") ? "/usr/bin/true" : "/bin/true";
  if (!PathExists(true_path)) return false;

  std::vector<std::string> storage;
  storage.reserve(64);
  auto push = [&](const std::string& value) { storage.push_back(value); };
  push(systemd_run);
  push("--user");
  push("--quiet");
  push("--scope");
  push("-p");
  push(std::string("TasksMax=") + kPidsMax);
  push("--");
  push(bwrap);
  push("--die-with-parent");
  // Create a user namespace before unsharing networking. Hosted Linux runners
  // otherwise lack CAP_NET_ADMIN for bwrap's loopback setup and reject the
  // same cage a regular desktop user is permitted to create.
  push("--unshare-user");
  push("--uid");
  push("0");
  push("--gid");
  push("0");
  push("--unshare-pid");
  push("--unshare-net");
  // Probe binds ONLY the true binary (not /usr/bin), proving libs resolve
  // without a live host bin directory.
  push("--ro-bind");
  push(true_path);
  push(true_path);
  AppendSystemBinds(&storage, false, "/var/empty");
  push("--chdir");
  push("/");
  push("--");
  push(true_path);
  return RunArgv(storage, environ) == 0;
}

void AppendChildEnv(std::vector<std::string>* storage, const LaunchConfig& config) {
  for (const auto& [key, value] : config.env) {
    storage->push_back("--setenv");
    storage->push_back(key);
    storage->push_back(value);
  }
}

int LaunchBwrap(const LaunchConfig& config) {
  const std::string bwrap = FindBwrap();
  const std::string systemd_run = FindSystemdRun();
  if (bwrap.empty()) return 70;
  if (systemd_run.empty()) return 71;
  if (!PathExists(config.workspace.c_str()) || !PathExists(config.application.c_str())) return 72;
  // Application must live under the staged workspace — never a live host path.
  if (config.application.compare(0, config.workspace.size(), config.workspace) != 0 ||
      (config.application.size() > config.workspace.size() &&
       config.application[config.workspace.size()] != '/')) {
    return 72;
  }
  if (config.cwd.compare(0, config.workspace.size(), config.workspace) != 0 ||
      (config.cwd.size() > config.workspace.size() && config.cwd[config.workspace.size()] != '/')) {
    return 72;
  }

  std::vector<std::string> storage;
  storage.reserve(96 + config.args.size() * 2 + config.env.size() * 3);
  auto push = [&](const std::string& value) { storage.push_back(value); };
  push(systemd_run);
  push("--user");
  push("--quiet");
  push("--scope");
  push("-p");
  push(std::string("TasksMax=") + kPidsMax);
  push("--");
  push(bwrap);
  push("--die-with-parent");
  push("--unshare-user");
  push("--uid");
  push("0");
  push("--gid");
  push("0");
  push("--unshare-pid");
  if (!config.network) push("--unshare-net");
  push("--bind");
  push(config.workspace);
  push(config.workspace);
  AppendSystemBinds(&storage, config.network, config.workspace);
  // Child env is set inside bwrap so systemd-run keeps the parent's
  // DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR for the user bus.
  // clearenv first, then --setenv (bwrap applies flags in order).
  push("--clearenv");
  AppendChildEnv(&storage, config);
  push("--chdir");
  push(config.cwd);
  push("--");
  push(config.application);
  for (const auto& arg : config.args) push(arg);

  // Parent environ for systemd-run (needs the session bus).
  return RunArgv(storage, environ);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--probe") == 0) return ProbeOnce() ? 0 : 1;
  if (argc == 3 && std::strcmp(argv[1], "--config") == 0) {
    LaunchConfig config;
    if (!ReadConfig(argv[2], &config)) return 65;
    // A provider token exists in the config only until this point.
    ::unlink(argv[2]);
    return LaunchBwrap(config);
  }
  return 64;  // EX_USAGE: fail closed for every unimplemented interface.
}
