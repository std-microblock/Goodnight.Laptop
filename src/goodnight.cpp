#include "goodnight/goodnight.h"
#include "goodnight/logger.h"
#include "goodnight/placeholder-window.h"

#include <algorithm>
#include <array>
#include <expected>
#include <filesystem>
#include <format>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <print>
#include <string_view>
#include <thread>

// Windows Stuff
#include "Windows.h"
#include "cfgmgr32.h"
#include "winevt.h"
#include <devguid.h>
#include <setupapi.h>
#include <tlhelp32.h>

#include <initguid.h>

#include "devpkey.h"

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
    goodnight::PlaceholderWindow window(
        [&](auto hwnd, auto msg, auto wparam, auto lparam) {
          std::lock_guard lock(this->msgMutex);

          if (*destructed) {
            return;
          }
          if (msg == WM_POWERBROADCAST) {
            switch ((long long)wparam) {
            case 32787:
              PPOWERBROADCAST_SETTING setting =
                  reinterpret_cast<PPOWERBROADCAST_SETTING>(lparam);

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
        });
    if (!RegisterPowerSettingNotification((HWND)window.hWnd,
                                          &GUID_LIDSWITCH_STATE_CHANGE,
                                          DEVICE_NOTIFY_WINDOW_HANDLE)) {
      goodnight::Logger::error(
          "Failed to register power setting notification: {}", GetLastError());
    }
    while (GetMessage(&msg, (HWND)window.hWnd, 0, 0)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
      if (*destructed) {
        return;
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
      // WaitForSingleObject(evt, INFINITE);
      Sleep(100);
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
          auto eventTime = extractStr("<TimeCreated SystemTime='", "' />");

          // parse the event time
          std::chrono::system_clock::time_point timePoint;
          {
            std::tm tm = {};
            std::istringstream ss(eventTime);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S.%f");
            timePoint =
                std::chrono::system_clock::from_time_t(std::mktime(&tm));
          }

          // time till now
          auto timeTillNow = std::chrono::system_clock::now() - timePoint;
          if (timeTillNow > std::chrono::seconds(3)) {
            Logger::info("Event {}(EventId-{}) is too old, skip", eventRecordId,
                         eventId);
            continue;
          }

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
  if (auto res = updateDisableDevices(config); !res) {
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
            Logger::info("We were woken up. The reason WakeupActions({}) is "
                         "not in the wakeup "
                         "actions, sleep back 5 seconds later...",
                         static_cast<int>(reason));
            std::this_thread::sleep_for(std::chrono::seconds(5));
            StandbyManager::sleep();
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
        } else if (auto *baseEvent =
                       std::get_if<PowerListener::BaseWindowsEvent>(&event)) {
          // Logger::info("Unknown event");
          Logger::debug("PowerListener::BaseWindowsEvent event: {}",
                        baseEvent->detail);
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

  auto systemProcNameList = {"OpenConsole.exe",     "conhost.exe",
                             "WindowsTerminal.exe", "cmd.exe",
                             "powershell.exe",      "pwsh.exe"};

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

static std::expected<void, std::string>
disableOrEnableDevice(const goodnight::DeviceManager::DeviceInfo &device,
                      bool disable) {
  auto hDevInfo = reinterpret_cast<HDEVINFO>(device.hDevInfo);
  auto DeviceInfoDatax = *reinterpret_cast<SP_DEVINFO_DATA *>(
      const_cast<DeviceManager::DEVINFO_TYPE *>(&device.devInfo));

  SP_PROPCHANGE_PARAMS params;
  params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
  params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
  params.Scope = DICS_FLAG_GLOBAL;
  params.StateChange = disable ? DICS_DISABLE : DICS_ENABLE;
  params.HwProfile = 0;
  if (!SetupDiSetClassInstallParams(hDevInfo, &DeviceInfoDatax,
                                    (SP_CLASSINSTALL_HEADER *)&params,
                                    sizeof(params))) {
    return std::unexpected(std::format(
        "SetupDiSetClassInstallParams failed with {}", GetLastError()));
  }
  params.Scope = DICS_FLAG_CONFIGSPECIFIC;
  if (!SetupDiSetClassInstallParams(hDevInfo, &DeviceInfoDatax,
                                    (SP_CLASSINSTALL_HEADER *)&params,
                                    sizeof(params))) {
    return std::unexpected(std::format(
        "SetupDiSetClassInstallParams failed with {}", GetLastError()));
  }

  if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo,
                                 &DeviceInfoDatax)) {
    if (GetLastError() == ERROR_NOT_DISABLEABLE) {
      Logger::error("Failed to disable/enable device \"{}\" because it's not "
                    "disableable. Skipping...",
                    device.deviceDesc);
    } else if (GetLastError() == ERROR_NO_SUCH_DEVINST) {
      Logger::error("Failed to disable/enable device \"{}\" because it "
                    "no more exists. Skipping...",
                    device.deviceDesc);
    } else {
      return std::unexpected(
          std::format("SetupDiCallClassInstaller failed with {}",
                      GetLastError())
              .c_str());
    }
  }

  return {};
}

std::expected<void, std::string> DeviceManager::switchHIDDevices(
    std::function<std::optional<bool>(DeviceInformationBasic &)> pred) {
  HDEVINFO hDevInfo;
  SP_DEVINFO_DATA DeviceInfoData;
  DWORD i;
  SP_PROPCHANGE_PARAMS
  params;
  hDevInfo = SetupDiGetClassDevs(NULL, 0, 0, DIGCF_ALLCLASSES);

  if (hDevInfo == INVALID_HANDLE_VALUE) {
    return std::unexpected("SetupDiGetClassDevs failed");
  }
  DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
  for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++) {
    auto getBuf =
        [&](auto property) -> std::expected<std::string, std::string> {
      DWORD DataT;
      DWORD buffersize = 0;
      std::wstring buf{};
      SetupDiGetDeviceRegistryPropertyW(hDevInfo, &DeviceInfoData, property,
                                        &DataT, (PBYTE)buf.data(), buffersize,
                                        &buffersize);
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        buf.resize(buffersize * 2);
      } else {
        return std::unexpected(std::format(
            "SetupDiGetDeviceRegistryProperty get buffer size failed with {}",
            GetLastError()));
      }

      while (!SetupDiGetDeviceRegistryPropertyW(
          hDevInfo, &DeviceInfoData, property, &DataT, (PBYTE)buf.data(),
          buffersize, &buffersize)) {
        return std::unexpected(std::format(
            "SetupDiGetDeviceRegistryProperty failed with {}", GetLastError()));
      }
      try {
        auto s = std::filesystem::path(buf).string();
        // resize to remove the null terminator
        return s.substr(0, s.find_first_of('\0'));
      } catch (std::exception &e) {
        return std::unexpected(
            std::format("Failed to convert path: {}", e.what()));
      }
    };

    auto deviceService = getBuf(SPDRP_SERVICE);
    auto deviceDesc = getBuf(SPDRP_DEVICEDESC);
    auto capabilites = getBuf(SPDRP_CAPABILITIES);
    auto classname = getBuf(SPDRP_CLASS);
    auto deviceId = getBuf(SPDRP_HARDWAREID);

    bool has_enabled = true;
    {
      ULONG status = 0, problem = 0;
      CONFIGRET cr =
          CM_Get_DevNode_Status(&status, &problem, DeviceInfoData.DevInst, 0);
      if (CR_SUCCESS == cr) {
        if (problem == CM_PROB_DISABLED) {
          has_enabled = false;
        } else {
          DEVPROPTYPE propertyType;
          const DWORD propertyBufferSize = 100;
          BYTE propertyBuffer[propertyBufferSize] = {0};
          DWORD requiredSize = 0;

          if (SetupDiGetDevicePropertyW(hDevInfo, &DeviceInfoData,
                                        &DEVPKEY_Device_ProblemCode,
                                        &propertyType, propertyBuffer,
                                        propertyBufferSize, &requiredSize, 0)) {
            unsigned long deviceProblemCode =
                *reinterpret_cast<unsigned long *>(propertyBuffer);
            if (deviceProblemCode == CM_PROB_DISABLED) {
              has_enabled = false;
            }
          }
        }
      }
    }

    DeviceInformationBasic info{
        .deviceDesc = deviceDesc.has_value() ? deviceDesc.value() : "",
        .className = classname.has_value() ? classname.value() : "",
        .deviceService = deviceService.has_value() ? deviceService.value() : "",
        .hwid = deviceId.has_value() ? deviceId.value() : "",
        .enabled = has_enabled,
    };

    auto enable = pred(info);

    auto devInfo = DeviceInfo{
        .devInfo = *reinterpret_cast<DEVINFO_TYPE *>(&DeviceInfoData),
        .deviceDesc = deviceDesc.has_value() ? deviceDesc.value() : "",
        .className = classname.has_value() ? classname.value() : "",
        .hDevInfo = hDevInfo,
        .hwid = info.hwid};
    auto existingOne =
        std::ranges::find_if(hidDevicesDisabled, [&](auto &device) {
          return device.hwid == devInfo.hwid;
        });

    if (!enable.has_value() && existingOne != hidDevicesDisabled.end()) {
      if (auto res = disableOrEnableDevice(devInfo, false); !res) {
        return res;
      }

      hidDevicesDisabled.erase(existingOne);
    } else if (enable.has_value() && *enable != has_enabled) {
      Logger::info("{} device[{}]: {}", *enable ? "Enabling" : "Disabling",
                   classname.value(), deviceDesc.value());
      if (auto res = disableOrEnableDevice(devInfo, !*enable); !res) {
        return res;
      }

      // Track Goodnight managed devices
      if (!*enable) {
        if (existingOne == hidDevicesDisabled.end()) {
          hidDevicesDisabled.push_back(devInfo);
        }
      } else {
        if (existingOne != hidDevicesDisabled.end()) {
          hidDevicesDisabled.erase(existingOne);
        }
      }
    }
  }
  SetupDiDestroyDeviceInfoList(hDevInfo);
  return {};
}
std::expected<void, std::string> DeviceManager::restoreHIDDevices() {
  if (auto res = switchHIDDevices([this](auto dev) -> std::optional<bool> {
        if (std::ranges::find_if(hidDevicesDisabled, [&](auto &device) {
              return device.hwid == dev.hwid;
            }) != hidDevicesDisabled.end()) {
          return std::optional<bool>{true};
        }
        return std::nullopt;
      });
      !res) {
    return res;
  }

  for (auto &device : hidDevicesDisabled) {
    Logger::info("Device[{}]: {} cannot be restored.", device.className,
                 device.deviceDesc);
  }

  return {};
}
Daemon::expected Daemon::updateDisableDevices(const Config &new_config) {
  if (new_config.disableDevices) {
    if (!config.disableDevices ||
        (new_config.wakeupActions != config.wakeupActions)) {
      if (!deviceManager) {
        deviceManager = std::make_unique<DeviceManager>();
      }
      powerListenerDisableDevices = std::make_unique<PowerListener>();
      powerListenerDisableDevices->addListener([this](auto event) {
        if (auto *exitEvent =
                std::get_if<PowerListener::ExitModernStandbyEvent>(&event)) {
          auto action = ToWakeupAction(exitEvent->reason);
          if (config.wakeupActions.contains(action)) {
            auto res = deviceManager->restoreHIDDevices();
            if (!res) {
              Logger::error("Failed to restore devices: {}", res.error());
            }
          }
        } else if (auto *enterEvent =
                       std::get_if<PowerListener::EnterModernStandbyEvent>(
                           &event)) {
          // WakeupAction:: Mouse->Mouse, Keyboard->Keyboard
          std::vector<std::string> devClassesToDisable{};
          using WA = Daemon::Config::WakeupActions;

          auto runSwitch = [&]() {
            auto res = deviceManager->switchHIDDevices(
                [&](auto &device) -> std::optional<bool> {
                  return std::ranges::contains(devClassesToDisable,
                                               device.className)
                             ? std::optional<bool>{false}
                             : std::nullopt;
                });
            if (!res) {
              Logger::error("Failed to disable devices: {}", res.error());
            }
          };

          if (!config.wakeupActions.contains(WA::Mouse)) {
            devClassesToDisable.push_back("Mouse");
          }

          if (!config.wakeupActions.contains(WA::Keyboard)) {
            devClassesToDisable.push_back("Keyboard");
          }

          runSwitch();
          devClassesToDisable.clear();

          if (!config.wakeupActions.contains(WA::TouchPad)) {
            auto res = deviceManager->switchHIDDevices(
                [&](DeviceManager::DeviceInformationBasic &device)
                    -> std::optional<bool> {
                  return device.deviceDesc.contains(
                             std::filesystem::path(L"触摸板").string()) ||
                                 device.deviceDesc.contains("Touchpad")
                             ? std::optional<bool>{false}
                             : device.enabled;
                });

            if (!res) {
              Logger::error("Failed to disable touchpad devices: {}",
                            res.error());
            }
          }

          if (!config.wakeupActions.contains(WA::Other)) {
            devClassesToDisable.push_back("Bluetooth");
            devClassesToDisable.push_back("Net");
          }

          runSwitch();
        }
      });
      if (auto res = powerListenerDisableDevices->start(); !res) {
        return res;
      }
    }
  } else {
    deviceManager = nullptr;
    powerListenerDisableDevices = nullptr;
  }

  return {};
}
bool isAdministrator() {
  HANDLE hToken;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    return false;
  }

  TOKEN_ELEVATION elevation;
  DWORD dwSize;
  if (!GetTokenInformation(hToken, TokenElevation, &elevation,
                           sizeof(elevation), &dwSize)) {
    CloseHandle(hToken);
    return false;
  }

  CloseHandle(hToken);
  return elevation.TokenIsElevated;
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