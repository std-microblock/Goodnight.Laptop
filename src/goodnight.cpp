#include "goodnight/goodnight.h"
#include "goodnight/logger.h"
#include "goodnight/placeholder-window.h"

#include <expected>
#include <filesystem>
#include <format>
#include <iostream>
#include <map>
#include <mutex>
#include <print>
#include <string_view>

#include <thread>

// Windows Stuff
#include "Windows.h"
#include "winevt.h"
#include <tlhelp32.h>

#include "Psapi.h"

namespace goodnight {
LogLevel logLevel = LogLevel::INFO;

bool StandbyManager::displayOff() {
  PlaceholderWindow window;
  SendMessage((HWND)window.hWnd, WM_SYSCOMMAND, SC_MONITORPOWER, 1);
  return GetLastError() == 0;
}

bool StandbyManager::sleep() {
  PlaceholderWindow window;
  SendMessage((HWND)window.hWnd, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
  return GetLastError() == 0;
}

std::expected<void, std::string> PowerListener::start() {
  if (started) {
    return std::unexpected("PowerListener already started");
  }
  started = true;

  std::thread([this] {
    MSG msg;
    goodnight::PlaceholderWindow window;
    while (GetMessage(&msg, (HWND)window.hWnd, 0, 0)) {
      std::lock_guard lock(this->msgMutex);
      if (*destructed) {
        return;
      }
      if (msg.message == WM_POWERBROADCAST) {
        switch (msg.wParam) {
        case PBT_APMSUSPEND:
          PPOWERBROADCAST_SETTING setting =
              reinterpret_cast<PPOWERBROADCAST_SETTING>(msg.lParam);

          if (setting->PowerSetting == GUID_LIDSWITCH_STATE_CHANGE) {
            if (setting->Data[0] == 0) {
              emitEvent(LidEvent{true});
            } else {
              emitEvent(LidEvent{false});
            }
          }
          break;
        }
      }
    }
  }).detach();

  // listen to power events
  // Microsoft-Windows-Kernel-Power
  // https://docs.microsoft.com/en-us/windows/win32/power/event-constants
  // https://docs.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe
  auto evt = CreateEventA(nullptr, false, true, nullptr);
  auto sub = EvtSubscribe(
      nullptr, evt, L"System",
      L"*[System[Provider[@Name='Microsoft-Windows-Kernel-Power']]]", nullptr,
      nullptr, nullptr, EvtSubscribeToFutureEvents);

  if (!sub) {
    return std::unexpected(
        std::format("EvtSubscribe failed with {}", GetLastError()));
  }

  auto thd = [this, sub, evt] {
    EVT_HANDLE events[1];
    DWORD returned;
    while (true) {
      WaitForSingleObject(evt, INFINITE);

      while (EvtNext(sub, 1, events, INFINITE, 0, &returned)) {
        std::lock_guard lock(this->msgMutex);
        if (*destructed) {
          EvtClose(sub);
          EvtClose(evt);
          return;
        }

        for (DWORD i = 0; i < returned; i++) {
          DWORD size;
          EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &size,
                    nullptr);
          std::wstring buffer(size, L'\0');
          EvtRender(nullptr, events[i], EvtRenderEventXml, size, buffer.data(),
                    &size, nullptr);
          std::string xmlStr = std::filesystem::path(buffer).string();

          auto extractStr = [&](std::string_view begin, std::string_view end) {
            auto pos = xmlStr.find(begin);
            if (pos == std::string::npos) {
              return std::string();
            }
            pos += begin.size();
            auto endPos = xmlStr.find(end, pos);
            if (endPos == std::string::npos) {
              return std::string();
            }
            return xmlStr.substr(pos, endPos - pos);
          };

          auto eventRecordId =
              std::stoul(extractStr("<EventRecordID>", "</EventRecordID>"));
          auto eventId = std::stoul(extractStr("<EventID>", "</EventID>"));

          switch (static_cast<EventID>(eventId)) {
          case EventID::ExitModernStandby: {
            auto reason =
                std::stoul(extractStr("<Data Name='Reason'>", "</Data>"));
            auto reasonEnum = ExitModernStandbyEvent::fromEventReason(reason);
            emitEvent(ExitModernStandbyEvent{{eventRecordId, eventId, xmlStr},
                                             reasonEnum});

            break;
          }
          case EventID::EnterModernStandby: {
            auto reason =
                std::stoul(extractStr("<Data Name='Reason'>", "</Data>"));
            auto batteryRemainingCapacityOnEnter = std::stoul(extractStr(
                "<Data Name='BatteryRemainingCapacityOnEnter'>", "</Data>"));
            auto batteryFullChargeCapacityOnEnter = std::stoul(extractStr(
                "<Data Name='BatteryFullChargeCapacityOnEnter'>", "</Data>"));

            emitEvent(
                EnterModernStandbyEvent{{eventRecordId, eventId, xmlStr},
                                        reason,
                                        batteryRemainingCapacityOnEnter,
                                        batteryFullChargeCapacityOnEnter});
            break;
          }
          case EventID::PowerChange: {
            auto acOnline =
                extractStr("<Data Name='AcOnline'>", "</Data>") == "true";
            emitEvent(
                PowerChangeEvent{{eventRecordId, eventId, xmlStr}, acOnline});
            break;
          }
          default: {
            emitEvent(BaseWindowsEvent{eventRecordId, eventId, xmlStr});
            break;
          }
          }
        }
      }
    }
  };
  std::thread(thd).detach();

  return {};
}
PowerListener::ExitModernStandbyEvent::Reason
PowerListener::ExitModernStandbyEvent::fromEventReason(uint32_t reason) {
  switch (reason) {
  case 32:
    return ExitModernStandbyEvent::Reason::Mouse;
  case 31:
    return ExitModernStandbyEvent::Reason::Keyboard;
  case 33:
    return ExitModernStandbyEvent::Reason::TouchPad;
  case 1:
    return ExitModernStandbyEvent::Reason::PowerButton;
  case 5:
    return ExitModernStandbyEvent::Reason::ACDCPower;
  case 20:
    return ExitModernStandbyEvent::Reason::Hibernate;
  case 15:
    return ExitModernStandbyEvent::Reason::Lid;
  case 44:
    return ExitModernStandbyEvent::Reason::FingerPrint;
  default:
    return ExitModernStandbyEvent::Reason::Unknown;
  }
}
void PowerListener::emitEvent(Events event) {
  for (auto &handler : listeners) {
    handler(event);
  }
}
void PowerListener::operator+=(std::function<void(Events)> listener) {
  addListener(listener);
}

std::expected<void, std::string> Daemon::updateConfig(const Config &config) {
  if (auto res = updateKeepSleep(config); !res) {
    return res;
  }
  if (auto res = updateSuspendProcesses(config); !res) {
    return res;
  }
  if (auto res = updateWakeLog(config); !res) {
    return res;
  }
  this->config = config;
  return {};
}
PowerListener::~PowerListener() {
  *destructed = true;
  std::lock_guard lock(this->msgMutex);
}
Daemon::expected Daemon::updateKeepSleep(const Config &new_config) {
  if (new_config.keepSleep) {
    if (!config.keepSleep || new_config.wakeupActions != config.wakeupActions) {
      powerListenerKeepSleep = std::make_unique<PowerListener>();
      powerListenerKeepSleep->addListener([this](auto event) {
        if (auto *exitEvent =
                std::get_if<PowerListener::ExitModernStandbyEvent>(&event)) {
          auto reason = ToWakeupAction(exitEvent->reason);

          if (!config.wakeupActions.contains(reason)) {
            StandbyManager::sleep();
            Logger::info("We were woken up. The reason {} is not in the wakeup "
                         "actions, sleep back now...",
                         static_cast<int>(reason));
          }
        }
      });

      if (auto res = powerListenerKeepSleep->start(); !res) {
        return res;
      }
    }
  } else {
    powerListenerKeepSleep = nullptr;
  }
  return {};
}
std::expected<void, std::string> SuspenseManager::suspendProcess(size_t pid,
                                                                 bool trace) {

  if constexpr (false) {
    // Fake implementation to test the daemon
    // get the name and path of the process
    HANDLE hProcessx =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcessx) {
      return std::unexpected("Failed to open process");
    }

    std::wstring pathBuf(MAX_PATH, L'\0');
    DWORD size =
        GetProcessImageFileNameW(hProcessx, pathBuf.data(), pathBuf.size());
    pathBuf.resize(size);

    auto processPath = std::filesystem::path(pathBuf);
    Logger::info("Suspend process: {}", processPath.string());

    return {};
  }

  if (suspendedProcesses.contains(pid)) {
    return {};
  }
  if (trace)
    suspendedProcesses.insert(pid);

  typedef LONG(NTAPI * NtSuspendProcess)(IN HANDLE ProcessHandle);
  static auto NtSuspendProcessPtr = (NtSuspendProcess)GetProcAddress(
      GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");

  if (!NtSuspendProcessPtr) {
    return std::unexpected("Failed to get NtSuspendProcess");
  }

  HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
  if (!hProcess) {
    return std::unexpected("Failed to open process");
  }

  if (auto res = NtSuspendProcessPtr(hProcess); res != 0) {
    return std::unexpected(std::format("NtSuspendProcess failed with {}", res));
  }

  return {};
}
std::expected<void, std::string> SuspenseManager::continueProcess(size_t pid,
                                                                  bool trace) {

  if (!suspendedProcesses.contains(pid)) {
    return {};
  }
  if (trace)
    suspendedProcesses.erase(pid);

  typedef LONG(NTAPI * NtResumeProcess)(IN HANDLE ProcessHandle);
  static auto NtResumeProcessPtr = (NtResumeProcess)GetProcAddress(
      GetModuleHandleA("ntdll.dll"), "NtResumeProcess");

  if (!NtResumeProcessPtr) {
    return std::unexpected("Failed to get NtResumeProcess");
  }

  HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
  if (!hProcess) {
    return std::unexpected("Failed to open process");
  }

  if (auto res = NtResumeProcessPtr(hProcess); res != 0) {
    return std::unexpected(std::format("NtResumeProcess failed with {}", res));
  }

  return {};
}
SuspenseManager::BatchOperationResult
SuspenseManager::suspendProcess(std::unordered_set<size_t> pids) {
  std::vector<std::pair<size_t, std::string>> errors;
  for (auto pid : pids) {
    if (auto res = suspendProcess(pid); !res) {
      errors.push_back({pid, res.error()});
    }
  }
  return errors;
}
SuspenseManager::BatchOperationResult
SuspenseManager::continuedProcess(std::unordered_set<size_t> pids) {
  std::vector<std::pair<size_t, std::string>> errors;
  for (auto pid : pids) {
    if (auto res = continueProcess(pid); !res) {
      errors.push_back({pid, res.error()});
    }
  }
  return errors;
}
SuspenseManager::BatchOperationResult SuspenseManager::restoreAllOperations() {
  std::vector<std::pair<size_t, std::string>> errors;
  for (auto pid : suspendedProcesses) {
    if (auto res = continueProcess(pid, false); !res) {
      errors.push_back({pid, res.error()});
    }
  }
  suspendedProcesses.clear();
  return errors;
}
std::unordered_set<size_t> SuspenseManager::allProcesses() {
  std::unordered_set<size_t> pids;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) {
    return pids;
  }

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!Process32First(hSnapshot, &pe32)) {
    CloseHandle(hSnapshot);
    return pids;
  }

  do {
    pids.insert(pe32.th32ProcessID);
  } while (Process32Next(hSnapshot, &pe32));

  CloseHandle(hSnapshot);
  return pids;
}
size_t SuspenseManager::selfPid() { return GetCurrentProcessId(); }
SuspenseManager::~SuspenseManager() { restoreAllOperations(); }
void PowerListener::addListener(std::function<void(Events)> listener) {
  listeners.push_back(listener);
}
Daemon::expected Daemon::updateSuspendProcesses(const Config &new_config) {
  if (new_config.suspendProcesses) {
    if (!config.suspendProcesses) {
      powerListenerSuspendProcesses = std::make_unique<PowerListener>();
      suspenseManager = std::make_unique<SuspenseManager>();

      powerListenerSuspendProcesses->addListener([this](auto event) {
        if (auto *exitEvent =
                std::get_if<PowerListener::ExitModernStandbyEvent>(&event)) {
          auto action = ToWakeupAction(exitEvent->reason);
          if (config.wakeupActions.contains(action)) {
            auto res = suspenseManager->restoreAllOperations();
            for (auto &[pid, error] : res) {
              Logger::info("Failed to restore process {}: {}", pid, error);
            }
          }
        } else if (auto *enterEvent =
                       std::get_if<PowerListener::EnterModernStandbyEvent>(
                           &event)) {
          auto allPids = suspenseManager->allNonSystemProcesses();
          auto selfPid = suspenseManager->selfPid();
          allPids.erase(selfPid);
          auto res = suspenseManager->suspendProcess(allPids);
          for (auto &[pid, error] : res) {
            Logger::info("Failed to suspend process {}: {}", pid, error);
          }
        }
      });

      if (auto res = powerListenerSuspendProcesses->start(); !res) {
        return res;
      }
    }
  } else {
    suspenseManager = nullptr;
    powerListenerSuspendProcesses = nullptr;
  }

  return {};
}
Daemon::expected Daemon::updateWakeLog(const Config &new_config) {
  if (new_config.wakeLog) {
    if (!powerListenerWakeLog) {
      powerListenerWakeLog = std::make_unique<PowerListener>();
      powerListenerWakeLog->addListener([this](PowerListener::Events event) {
        if (auto *exitEvent =
                std::get_if<PowerListener::ExitModernStandbyEvent>(&event)) {
          Logger::info("Exit Modern Standby. Reason: {}",
                       static_cast<int>(exitEvent->reason));
          Logger::debug("PowerListener::ExitModernStandbyEvent event: {}",
                        exitEvent->detail);
        } else if (auto *enterEvent =
                       std::get_if<PowerListener::EnterModernStandbyEvent>(
                           &event)) {
          Logger::info("Enter Modern Standby. Reason: {}",
                       static_cast<int>(enterEvent->reason));
          Logger::debug("PowerListener::EnterModernStandbyEvent event: {}",
                        enterEvent->detail);
        } else if (auto *powerEvent =
                       std::get_if<PowerListener::PowerChangeEvent>(&event)) {
          Logger::info("Power Change: {}", powerEvent->acOnline ? "AC" : "DC");
          Logger::debug("PowerListener::PowerChangeEvent event: {}",
                        powerEvent->detail);
        } else if (auto *lidEvent =
                       std::get_if<PowerListener::LidEvent>(&event)) {
          Logger::info("Lid: {}", lidEvent->closed ? "Closed" : "Opened");
        } else {
          // Logger::info("Unknown event");
        }
      });

      if (auto res = powerListenerWakeLog->start(); !res) {
        return res;
      }
    }
  } else {
    powerListenerWakeLog.reset();
  }
  return {};
}

bool isPathParentOf(const std::filesystem::path &parent,
                    const std::filesystem::path &child) {
  auto parentIt = parent.begin();
  auto childIt = child.begin();
  for (; parentIt != parent.end() && childIt != child.end();
       ++parentIt, ++childIt) {
    if (*parentIt != *childIt) {
      return false;
    }
  }
  return parentIt == parent.end();
}
// processes that are in system directory, cannot be opened with SUSPEND_RESUME,
// with specific names, are considered as system processes
bool SuspenseManager::isSystemProcess(size_t pid) {
  auto hProcess = OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, pid);
  if (!hProcess) {
    return true;
  }

  std::wstring pathBuf(MAX_PATH, L'\0');
  DWORD size =
      GetProcessImageFileNameW(hProcess, pathBuf.data(), pathBuf.size());
  pathBuf.resize(size);

  auto processPath = std::filesystem::path(pathBuf);

  auto systemProcNameList = {"OpenConsole.exe", "conhost.exe",
                             "WindowsTerminal.exe", "cmd.exe"};

  return processPath.string().contains("\\Windows\\") ||
         processPath.string().contains("\\System32\\") ||
         std::ranges::any_of(systemProcNameList, [&](auto name) {
           return processPath.filename().string().contains(name);
         });
}
std::unordered_set<size_t> SuspenseManager::allNonSystemProcesses() {
  auto all = allProcesses();
  std::unordered_set<size_t> nonSystem;
  for (auto pid : all) {
    if (!isSystemProcess(pid)) {
      nonSystem.insert(pid);
    }
  }
  return nonSystem;
}
size_t SuspenseManager::processFromName(std::string_view name) {
  auto all = allProcesses();
  for (auto pid : all) {
    HANDLE hProcess =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
      continue;
    }

    std::wstring pathBuf(MAX_PATH, L'\0');
    DWORD size =
        GetProcessImageFileNameW(hProcess, pathBuf.data(), pathBuf.size());
    pathBuf.resize(size);

    auto processPath = std::filesystem::path(pathBuf);
    if (processPath.filename().string().contains(name)) {
      return pid;
    }
  }
  return 0;
}
std::unordered_set<size_t> SuspenseManager::selfTree() {
  // get the parent process id and the parent of the parent process id....
  std::map<size_t, size_t> tree;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) {
    return {};
  }

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!Process32First(hSnapshot, &pe32)) {
    CloseHandle(hSnapshot);
    return {};
  }

  do {
    tree[pe32.th32ProcessID] = pe32.th32ParentProcessID;
  } while (Process32Next(hSnapshot, &pe32));

  CloseHandle(hSnapshot);

  std::unordered_set<size_t> pids;
  size_t selfPid = GetCurrentProcessId();
  pids.insert(selfPid);
  while (tree.contains(selfPid)) {
    selfPid = tree[selfPid];
    pids.insert(selfPid);
  }

  return pids;
}
} // namespace goodnight

bool goodnight::startMessageLoop() {
  MSG msg;
  while (true) {
    GetMessage(&msg, nullptr, 0, 0);
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
}