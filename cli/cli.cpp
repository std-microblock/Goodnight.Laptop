#include "lyra/cli.hpp"
#include "goodnight/goodnight.h"
#include "goodnight/logger.h"

#include "lyra/lyra.hpp"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <ranges>
#include <thread>
#include <vector>

std::expected<goodnight::Daemon::Config::WakeupActions, std::string>
toWakeupAction(const std::string &action) {
  if (action == "DisplayOn") {
    return goodnight::Daemon::Config::WakeupActions::DisplayOn;
  } else if (action == "PowerButton") {
    return goodnight::Daemon::Config::WakeupActions::PowerButton;
  } else if (action == "Keyboard") {
    return goodnight::Daemon::Config::WakeupActions::Keyboard;
  } else if (action == "Mouse") {
    return goodnight::Daemon::Config::WakeupActions::Mouse;
  } else if (action == "TouchPad") {
    return goodnight::Daemon::Config::WakeupActions::TouchPad;
  } else if (action == "ACDCPower") {
    return goodnight::Daemon::Config::WakeupActions::PowerAction;
  } else if (action == "Other") {
    return goodnight::Daemon::Config::WakeupActions::Other;
  } else {
    return std::unexpected("Invalid wakeup action: " + action);
  }
}

std::string
wakeActionToHumanReadable(goodnight::Daemon::Config::WakeupActions action) {
  switch (action) {
  case goodnight::Daemon::Config::WakeupActions::DisplayOn:
    return "when the display turns on";
  case goodnight::Daemon::Config::WakeupActions::PowerButton:
    return "when the power button is pressed";
  case goodnight::Daemon::Config::WakeupActions::Keyboard:
    return "when a key is pressed";
  case goodnight::Daemon::Config::WakeupActions::Mouse:
    return "when the mouse is moved or clicked";
  case goodnight::Daemon::Config::WakeupActions::TouchPad:
    return "when the touchpad is touched";
  case goodnight::Daemon::Config::WakeupActions::PowerAction:
    return "when the power plugged in or out";
  case goodnight::Daemon::Config::WakeupActions::Other:
    return "when any other action is taken";
  default:
    return "Unknown";
  }
}

void testDeviceDisableEnable() {
  using namespace goodnight;
  std::vector<std::string> devClassesToDisable{};
  using WA = Daemon::Config::WakeupActions;

  devClassesToDisable.push_back("Mouse");

  // devClassesToDisable.push_back("Keyboard");

  // devClassesToDisable.push_back("Bluetooth");
  // devClassesToDisable.push_back("USB");
  // devClassesToDisable.push_back("Net");

  auto deviceManager = std::make_unique<DeviceManager>();

  auto res =
      deviceManager->switchHIDDevices([&](auto &device) -> std::optional<bool> {
        return std::ranges::contains(devClassesToDisable, device.className)
                   ? std::optional<bool>{false}
                   : std::nullopt;
      });

  auto res2 = deviceManager->switchHIDDevices(
      [&](DeviceManager::DeviceInformationBasic &device)
          -> std::optional<bool> {
        return device.deviceDesc.contains(
                   std::filesystem::path(L"触摸板").string()) ||
                       device.deviceDesc.contains("Touchpad")
                   ? std::optional<bool>{false}
                   : device.enabled;
      });

  if (!res2) {
    Logger::error("Failed to disable touchpad devices: {}", res.error());
  }

  std::this_thread::sleep_for(std::chrono::seconds(5));
  if (auto res = deviceManager->restoreHIDDevices(); !res) {
    Logger::error("Failed to restore devices: {}", res.error());
  }
}

int main(int argc, char **argv) {
  try {
    std::cout << R"(
     ___                _     __ _       _     _   
    / _ \___   ___   __| | /\ \ (_) __ _| |__ | |_ 
   / /_\/ _ \ / _ \ / _` |/  \/ / |/ _` | '_ \| __|
  / /_\\ (_) | (_) | (_| / /\  /| | (_| | | | | |_ 
  \____/\___/ \___/ \__,_\_\ \/ |_|\__, |_| |_|\__|
                                   |___/           

    Goodnight CLI v0.1.1

)";

    bool keepSleep = false;
    bool wakeLog = false;
    bool suspendProcesses = false;
    bool help = false;
    bool verboseLog = false;
    bool disableDevices = false;
    auto wakeupActions = std::vector<std::string>{"DisplayOn", "PowerButton"};

    auto cli =
        lyra::cli() |
        lyra::opt(keepSleep)["-k"]["--keep-sleep"](
            "Keep the system in sleep mode") |
        lyra::opt(wakeLog)["-l"]["--wake-log"]("Log the wake events") |
        lyra::opt(suspendProcesses)["-s"]["--suspend-processes"](
            "Suspend processes on sleep") |
        lyra::opt(wakeupActions, "wakeupActions")["-wa"]["--wakeup-actions"](
            "Wakeup actions [DisplayOn, PowerButton, Keyboard, Mouse, "
            "TouchPad, "
            "ACDCPower, Other, All]") |
        lyra::opt(verboseLog)["-v"]["--verbose"]("Verbose log") |
        lyra::opt(disableDevices)["-d"]["--disable-devices"](
            "Disable devices on sleep") |
        lyra::help(help);

    auto result = cli.parse({argc, argv});

    if (!result) {
      std::cerr << "Error in command line: " << result.message() << std::endl;
      return 1;
    }

    if (help) {
      std::cout << cli;
      return 0;
    }

    if (verboseLog) {
      goodnight::logLevel = goodnight::LogLevel::DEBUG;
    }

    if (disableDevices && !goodnight::isAdministrator()) {
      goodnight::Logger::error("[-] You need to run as administrator to "
                               "disable devices, exiting after 3 seconds...");
      std::this_thread::sleep_for(std::chrono::seconds(3));
      return 1;
    }

    using WA = goodnight::Daemon::Config::WakeupActions;
    auto wakeupActionsSet = std::unordered_set<WA>{};
    for (const auto &action : wakeupActions) {
      if (auto res = toWakeupAction(action); res) {
        wakeupActionsSet.insert(res.value());
      } else {
        std::cerr << "Error in command line: " << res.error() << std::endl;
        return 1;
      }
    }

    goodnight::Daemon::Config config{};
    if (argc > 1) {
      config = {.keepSleep = keepSleep,
                .wakeupActions = wakeupActionsSet,
                .suspendProcesses = suspendProcesses,
                .wakeLog = wakeLog,
                .disableDevices = disableDevices};
    } else {
      goodnight::Logger::info("Using default config...");
      config = {.keepSleep = true,
                .wakeupActions =
                    {
                        WA::DisplayOn,
                        WA::PowerButton,
                    },
                .suspendProcesses = false,
                .wakeLog = true,
                .disableDevices = false};
    }

    // Output the config as a human readable string
    std::string configInfo = "As you configured, after getting into s0 sleep, ";
    if (config.keepSleep || config.wakeLog || config.suspendProcesses) {
      configInfo += "the daemon will ";
    }
    if (config.keepSleep) {
      configInfo += "keep the system in sleep mode, ";
    }
    if (config.wakeLog) {
      configInfo += "log the wake events, ";
    }
    if (config.suspendProcesses) {
      configInfo += "suspend processes on sleep, ";
    }
    if (config.keepSleep || config.wakeLog || config.suspendProcesses) {
      configInfo += "and ";
    }
    if (config.keepSleep) {
      configInfo += "only ";
      for (auto [i, action] : std::views::enumerate(config.wakeupActions)) {
        configInfo += wakeActionToHumanReadable(action);
        if (i == config.wakeupActions.size() - 2) {
          configInfo += " and ";
        } else {
          configInfo += ", ";
        }
      }
      configInfo += "will the system wake up. ";
    } else {
      configInfo += "the system will wake up for any action. ";
    }

    if (config.disableDevices) {
      configInfo += "Also, related devices will be disabled on sleep. ";
    }

    goodnight::Daemon daemon;
    if (auto res = daemon.updateConfig(config)) {
      goodnight::Logger::info("[+] Daemon started");
      goodnight::Logger::info("{}", configInfo);
    } else {
      goodnight::Logger::error("[-] Failed to start daemon: {}", res.error());
      return 1;
    }
    goodnight::startMessageLoop();
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}