// Probe whether this Linux host can run the Latch command cage:
// bubblewrap on PATH, plus systemd-run --user scopes with TasksMax (cgroup
// v2 process cap). The launcher owns the real cage; this addon only answers
// the availability question so the executor can fail closed before staging.
#include <napi.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

namespace {

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

void RoBindIfPresent(std::vector<std::string>* argv, const char* path) {
  if (!PathExists(path)) return;
  argv->push_back("--ro-bind");
  argv->push_back(path);
  argv->push_back(path);
}

bool ProbeCage() {
  const std::string bwrap = FindOnPath("bwrap");
  const std::string systemd_run = FindOnPath("systemd-run");
  if (bwrap.empty() || systemd_run.empty()) return false;
  const char* true_path = PathExists("/usr/bin/true") ? "/usr/bin/true" : "/bin/true";
  if (!PathExists(true_path)) return false;

  // Same library binds as the launcher: Debian/Ubuntu `true` is linked
  // against `/lib/x86_64-linux-gnu`, so a `/usr/lib`-only probe reports the
  // cage missing on a host that can actually run it.
  std::vector<std::string> args = {
      "systemd-run", "--user", "--quiet", "--scope", "-p", "TasksMax=256", "--",
      bwrap, "--die-with-parent",
      "--unshare-user", "--uid", "0", "--gid", "0",
      "--unshare-pid", "--unshare-net",
      "--ro-bind", true_path, true_path,
  };
  RoBindIfPresent(&args, "/usr/lib");
  RoBindIfPresent(&args, "/usr/lib64");
  RoBindIfPresent(&args, "/lib");
  RoBindIfPresent(&args, "/lib64");
  if (PathExists("/usr/lib") && !PathExists("/lib")) {
    args.insert(args.end(), {"--symlink", "usr/lib", "/lib"});
  }
  if (PathExists("/usr/lib") && !PathExists("/lib64")) {
    args.insert(args.end(), {"--symlink", "usr/lib", "/lib64"});
  }
  RoBindIfPresent(&args, "/etc/ld.so.cache");
  args.insert(args.end(), {
      "--dev", "/dev", "--proc", "/proc",
      "--cap-drop", "ALL", "--new-session", "--chdir", "/",
      "--", true_path,
  });

  const pid_t child = ::fork();
  if (child < 0) return false;
  if (child == 0) {
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& arg : args) argv.push_back(arg.data());
    argv.push_back(nullptr);
    ::execv(systemd_run.c_str(), argv.data());
    _exit(127);
  }
  int status = 1;
  if (::waitpid(child, &status, 0) < 0) return false;
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

Napi::Value Available(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), ProbeCage());
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("available", Napi::Function::New(env, Available));
  return exports;
}

NODE_API_MODULE(linuxsandbox, Init)

}  // namespace
