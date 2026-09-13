// Probe whether this Linux host can run the Latch command cage:
// bubblewrap on PATH, plus systemd-run --user scopes with TasksMax (cgroup
// v2 process cap). The launcher owns the real cage; this addon only answers
// the availability question so the executor can fail closed before staging.
#include <napi.h>

#include <cstdlib>
#include <cstring>
#include <string>
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

bool ProbeCage() {
  const std::string bwrap = FindOnPath("bwrap");
  const std::string systemd_run = FindOnPath("systemd-run");
  if (bwrap.empty() || systemd_run.empty()) return false;
  const char* true_path = PathExists("/usr/bin/true") ? "/usr/bin/true" : "/bin/true";
  if (!PathExists(true_path)) return false;

  const pid_t child = ::fork();
  if (child < 0) return false;
  if (child == 0) {
    ::execl(
        systemd_run.c_str(),
        "systemd-run",
        "--user",
        "--quiet",
        "--scope",
        "-p",
        "TasksMax=256",
        "--",
        bwrap.c_str(),
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-net",
        "--ro-bind", true_path, true_path,
        "--ro-bind", "/usr/lib", "/usr/lib",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib", "/lib64",
        "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--dev", "/dev",
        "--proc", "/proc",
        "--cap-drop", "ALL",
        "--new-session",
        "--chdir", "/",
        "--",
        true_path,
        static_cast<char*>(nullptr));
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
