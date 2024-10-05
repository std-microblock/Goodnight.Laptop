#pragma once
#include <bitset>
#include <cstdint>
#include <expected>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "placeholder-window.h"

namespace goodnight {
bool startMessageLoop();
bool isAdministrator();
struct StandbyManager {
  static bool displayOff();
  static bool sleep();
};

struct PowerListener {
  std::expected<void, std::string> start();

  enum class EventID {
    PowerChange = 105,
    ExitModernStandby = 507,
    EnterModernStandby = 506,
    SessionTransition = 566,
    Hibernate = 42,
  };

  struct BaseWindowsEvent {
    uint32_t eventRecordId;
    uint32_t eventId;
    std::string detail;
  };

  struct ExitModernStandbyEvent : public BaseWindowsEvent {
    enum class Reason {
      Mouse,
      Keyboard,
      TouchPad,
      PowerButton,
      ACDCPower,
      Hibernate,
      Lid,
      Unknown,
      FingerPrint,
    };

    Reason reason;
    static Reason fromEventReason(uint32_t reason);
  };

  struct EnterModernStandbyEvent : public BaseWindowsEvent {
    uint32_t reason;
    uint32_t BatteryRemainingCapacityOnEnter;
    uint32_t BatteryFullChargeCapacityOnEnter;
  };

  struct PowerChangeEvent : public BaseWindowsEvent {
    bool acOnline;
  };

  struct LidEvent {
    bool closed;
  };

  using Events = std::variant<ExitModernStandbyEvent, EnterModernStandbyEvent,
                              PowerChangeEvent, LidEvent, BaseWindowsEvent>;

  void operator+=(std::function<void(Events)> listener);
  void addListener(std::function<void(Events)> listener);

  ~PowerListener();
  void emitEvent(Events event);

private:
  bool started = false;
  std::vector<std::function<void(Events)>> listeners;

  std::shared_ptr<bool> destructed = std::make_shared<bool>(false);
  std::mutex msgMutex;
};

struct SuspenseManager {
  std::expected<void, std::string> suspendProcess(size_t pid,
                                                  bool trace = true);
  std::expected<void, std::string> continueProcess(size_t pid,
                                                   bool trace = true);

  using BatchOperationResult = std::vector<std::pair<size_t, std::string>>;
  BatchOperationResult suspendProcess(std::unordered_set<size_t> pids);
  BatchOperationResult continuedProcess(std::unordered_set<size_t> pids);
  BatchOperationResult restoreAllOperations();

  std::unordered_set<size_t> allProcesses();
  std::unordered_set<size_t> allNonSystemProcesses();
  std::unordered_set<size_t> selfTree();
  size_t processFromName(std::string_view name);
  size_t selfPid();
  bool isSystemProcess(size_t pid);
  ~SuspenseManager();

private:
  std::unordered_set<size_t> suspendedProcesses{};
};

struct DeviceManager {
  struct DeviceInformationBasic {
    std::string deviceDesc;
    std::string className;
    std::string deviceService;
    std::string hwid;
    bool enabled;
  };
  /**
   * @brief Disable or enable a device
   *
   * @param pred A predicate that returns true if the device should be disabled,
   *             false if it should be enabled, and std::nullopt if it should be
   *             left as is (Will be enabled if it was disabled by the manager)
   */
  std::expected<void, std::string> switchHIDDevices(
      std::function<std::optional<bool>(DeviceInformationBasic &)> pred);
  std::expected<void, std::string> restoreHIDDevices();

  struct DEVINFO_TYPE {
    int32_t cbSize;
    std::bitset<128> ClassGuid;
    int32_t DevInst;
    void *Reserved;
  };

  struct DeviceInfo {
    DEVINFO_TYPE devInfo;
    std::string deviceDesc;
    std::string className;
    void *hDevInfo;
    std::string hwid;
  };

private:
  std::vector<DeviceInfo> hidDevicesDisabled{};
};

struct Daemon {
  struct Config {
    enum class WakeupActions {
      None,
      DisplayOn,
      Keyboard,
      Mouse,
      TouchPad,
      PowerButton,
      PowerAction,
      Other,
    };

    bool keepSleep = false;
    std::unordered_set<WakeupActions> wakeupActions{
        Daemon::Config::WakeupActions::PowerButton};

    bool suspendProcesses = false;

    bool wakeLog = false;
    bool disableDevices = false;
    int sleepAfterLidCloseSeconds = 0;
  };
  using expected = std::expected<void, std::string>;
  expected updateConfig(const Config &config);
  inline bool isStarted() const { return started; }

private:
  bool started = false;
  Config config;

  std::unique_ptr<PowerListener> powerListenerKeepSleep = nullptr;

  std::unique_ptr<PowerListener> powerListenerSuspendProcesses = nullptr;
  std::unique_ptr<SuspenseManager> suspenseManager = nullptr;

  std::unique_ptr<PowerListener> powerListenerWakeLog = nullptr;

  std::unique_ptr<PowerListener> powerListenerDisableDevices = nullptr;
  std::unique_ptr<DeviceManager> deviceManager = nullptr;

  std::unique_ptr<PowerListener> powerListenerSleepAfterLidCloseSeconds =
      nullptr;

  Config::WakeupActions
  ToWakeupAction(PowerListener::ExitModernStandbyEvent::Reason reason) {
    if (reason == PowerListener::ExitModernStandbyEvent::Reason::Mouse) {
      return Config::WakeupActions::Mouse;
    } else if (reason ==
               PowerListener::ExitModernStandbyEvent::Reason::Keyboard) {
      return Config::WakeupActions::Keyboard;
    } else if (reason ==
               PowerListener::ExitModernStandbyEvent::Reason::TouchPad) {
      return Config::WakeupActions::TouchPad;
    } else if (reason ==
               PowerListener::ExitModernStandbyEvent::Reason::PowerButton) {
      return Config::WakeupActions::PowerButton;
    } else if (reason ==
               PowerListener::ExitModernStandbyEvent::Reason::ACDCPower) {
      return Config::WakeupActions::DisplayOn;
    } else if (reason ==
               PowerListener::ExitModernStandbyEvent::Reason::Hibernate) {
      return Config::WakeupActions::DisplayOn;
    } else if (reason == PowerListener::ExitModernStandbyEvent::Reason::Lid) {
      return Config::WakeupActions::DisplayOn;
    } else if (reason ==
               PowerListener::ExitModernStandbyEvent::Reason::FingerPrint) {
      return Config::WakeupActions::Other;
    } else {
      return Config::WakeupActions::None;
    }
  }
  expected updateKeepSleep(const Config &new_config);
  expected updateSuspendProcesses(const Config &new_config);
  expected updateWakeLog(const Config &new_config);
  expected updateDisableDevices(const Config &new_config);
  expected updateSleepAfterLidCloseSeconds(const Config &new_config);
};
} // namespace goodnight