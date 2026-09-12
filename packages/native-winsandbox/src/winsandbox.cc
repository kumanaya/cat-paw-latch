// One Windows Job Object per agent command run.
//
// What a job gives us, and what it does not: KILL_ON_JOB_CLOSE means closing
// the last handle ends every member process — the reaper's guarantee, so a
// run the app abandons cannot outlive it as a detached tree. ACTIVE_PROCESS
// caps the fork-bomb shape. What it is NOT: file confinement (seatbelt's
// file-read*/file-write* grants have no Job equivalent — that stays an
// approval-time bound enforced by FileOps for in-process tools and by the
// per-run environment here) and network gating (that needs WFP callouts, a
// driver-shaped change that is not this addon). The residual is documented
// in DESIGN.md §6, not hidden.
//
// Three functions, no policy: which pid goes into which job is the
// executor's decision. No delete-a-key shape here either: close(id) ends the
// run's processes, which is exactly what closing is for.
//
// Error contract: failures throw an Error whose `code` property is the Win32
// error (a pid that already belongs to a job arrives as
// ERROR_ACCESS_DENIED), so the caller can fail the run closed with a reason.
#include <napi.h>
#include <windows.h>
#include <userenv.h>

#include <cstdint>
#include <map>

namespace {

std::map<uint64_t, HANDLE> g_jobs;
uint64_t g_next = 1;

// Stated ceiling: a run is one command tree, not a build farm. A shell that
// fans out past this is either compromised or needs its approval revisited —
// either way refusing new processes is the safe direction.
constexpr DWORD kActiveProcessLimit = 256;

Napi::Error WinError(Napi::Env env, DWORD code, const char* what) {
  Napi::Error err =
      Napi::Error::New(env, std::string(what) + " failed (Win32 " + std::to_string(code) + ")");
  err.Set("code", Napi::Number::New(env, code));
  return err;
}

HANDLE Lookup(Napi::Env env, uint64_t id) {
  const auto it = g_jobs.find(id);
  if (it == g_jobs.end()) {
    throw Napi::Error::New(env, "unknown job id");
  }
  return it->second;
}

// create() -> number. An empty job with kill-on-close and a process cap.
Napi::Value Create(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job == nullptr) {
    throw WinError(env, GetLastError(), "CreateJobObjectW");
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags =
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  limits.BasicLimitInformation.ActiveProcessLimit = kActiveProcessLimit;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                               sizeof(limits))) {
    const DWORD code = GetLastError();
    CloseHandle(job);
    throw WinError(env, code, "SetInformationJobObject");
  }
  const uint64_t id = g_next++;
  g_jobs[id] = job;
  return Napi::Number::New(env, static_cast<double>(id));
}

// assign(id, pid) -> undefined. The child must not belong to a job already —
// Node-spawned children never do, so a failure here is a real surprise and
// the run is failed closed rather than run outside the job.
Napi::Value Assign(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  const uint64_t id = static_cast<uint64_t>(info[0].As<Napi::Number>().DoubleValue());
  const DWORD pid = static_cast<DWORD>(info[1].As<Napi::Number>().Uint32Value());
  HANDLE job = Lookup(env, id);
  HANDLE process =
      OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid);
  if (process == nullptr) {
    throw WinError(env, GetLastError(), "OpenProcess");
  }
  if (!AssignProcessToJobObject(job, process)) {
    const DWORD code = GetLastError();
    CloseHandle(process);
    throw WinError(env, code, "AssignProcessToJobObject");
  }
  CloseHandle(process);
  return env.Undefined();
}

// close(id) -> undefined. Closing the last handle kills every member
// process (KILL_ON_JOB_CLOSE): the run ends here, abandoned or not.
Napi::Value Close(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  const uint64_t id = static_cast<uint64_t>(info[0].As<Napi::Number>().DoubleValue());
  HANDLE job = Lookup(env, id);
  g_jobs.erase(id);
  CloseHandle(job);
  return env.Undefined();
}

// appContainerAvailable() -> boolean.  This is deliberately a real probe:
// the profile is created under the current user then immediately deleted. A
// Windows build that cannot perform both operations cannot safely promise the
// AppContainer launcher that will replace the Job-only path.
Napi::Value AppContainerAvailable(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  const std::wstring name = L"PlowLatch.Probe." + std::to_wstring(GetCurrentProcessId()) +
                            L"." + std::to_wstring(GetTickCount64());
  PSID sid = nullptr;
  const HRESULT created = CreateAppContainerProfile(name.c_str(), name.c_str(), L"Plow Latch probe", nullptr, 0, &sid);
  if (SUCCEEDED(created)) {
    FreeSid(sid);
    const HRESULT removed = DeleteAppContainerProfile(name.c_str());
    return Napi::Boolean::New(env, SUCCEEDED(removed));
  }
  // A same-name collision is impossible for this name, but the API itself is
  // present; all other failures (policy, disabled service, old OS) are an
  // unavailable security primitive and must make the caller fail closed.
  return Napi::Boolean::New(env, false);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("create", Napi::Function::New(env, Create));
  exports.Set("assign", Napi::Function::New(env, Assign));
  exports.Set("close", Napi::Function::New(env, Close));
  exports.Set("appContainerAvailable", Napi::Function::New(env, AppContainerAvailable));
  return exports;
}

NODE_API_MODULE(winsandbox, Init)

}  // namespace
