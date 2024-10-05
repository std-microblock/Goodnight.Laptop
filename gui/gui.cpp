#include <RmlUi/Core.h>
#include <RmlUi/Debugger.h>
#include <atomic>
#include <expected>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <memory>

#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "RmlUi/Include/RmlUi/Core/Core.h"
#include "RmlUi/Include/RmlUi/Core/ID.h"
#include "RmlUi/Include/RmlUi/Core/Span.h"
#include "RmlUi/Include/RmlUi/Core/SystemInterface.h"
#include "RmlUi/Include/RmlUi/Core/Variant.h"
#include "RmlUi/Source/Core/FontEngineDefault/FreeTypeInterface.h"
#include "RmlUi_Backend.h"

#include "RmlUi_Platform_GLFW.h"
#include "RmlUi_Renderer_GL3.h"
#include "freetype/freetype.h"
#include "freetype/internal/ftobjs.h"
#include "freetype/tttables.h"
#include "ft2build.h"

#include "goodnight/goodnight.h"
#include "goodnight/logger.h"

#include "FileWatch.hpp"

#define GLFW_EXPOSE_NATIVE_WIN32
// #include "RmlUi/Core/RenderInterface.h"
#include "GLFW/glfw3.h"
#include "GLFW/glfw3native.h"

#include "Windows.h"
#include "dwmapi.h"
#include "shellapi.h"
#include "wingdi.h"

constexpr bool development = true;
class SysInterf : public Rml::SystemInterface {
  bool LogMessage(Rml::Log::Type type, const Rml::String &message) override {
    goodnight::Logger::info("{}", message);
    return true;
  }
};

std::vector<std::filesystem::path> getSystemFonts() {
  std::vector<std::filesystem::path> fonts;

  std::string windowsPath(MAX_PATH, '\0');
  GetWindowsDirectoryA(windowsPath.data(), windowsPath.size());
  windowsPath.resize(strlen(windowsPath.c_str()));

  HKEY hKey;
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", 0,
                   KEY_READ, &hKey) == ERROR_SUCCESS) {
    DWORD index = 0;
    char valueName[16383];
    DWORD valueNameSize = 16383;
    DWORD valueType;
    BYTE valueData[16383];
    DWORD valueDataSize = 16383;
    while (RegEnumValue(hKey, index, valueName, &valueNameSize, NULL,
                        &valueType, valueData,
                        &valueDataSize) == ERROR_SUCCESS) {
      fonts.push_back(std::filesystem::path(windowsPath) / "Fonts" /
                      std::string(valueData, valueData + valueDataSize));
      index++;
      valueNameSize = 16383;
      valueDataSize = 16383;
    }
    RegCloseKey(hKey);
  }

  if (RegOpenKeyEx(HKEY_CURRENT_USER,
                   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", 0,
                   KEY_READ, &hKey) == ERROR_SUCCESS) {
    DWORD index = 0;
    char valueName[16383];
    DWORD valueNameSize = 16383;
    DWORD valueType;
    BYTE valueData[16383];
    DWORD valueDataSize = 16383;
    while (RegEnumValue(hKey, index, valueName, &valueNameSize, NULL,
                        &valueType, valueData,
                        &valueDataSize) == ERROR_SUCCESS) {
      fonts.push_back(std::filesystem::path(
          std::string(valueData, valueData + valueDataSize)));
      index++;
      valueNameSize = 16383;
      valueDataSize = 16383;
    }
    RegCloseKey(hKey);
  }

  return fonts;
}

struct FontFace {
  std::string name;
  std::string style;
  int weight;
  std::string file;
};

std::vector<FontFace> getFontFaces() {
  auto fonts = getSystemFonts();
  std::vector<FontFace> fontFaces;
  FT_Library library;
  FT_Init_FreeType(&library);
  for (auto &font : fonts) {
    FT_Face face;
    if (!FT_New_Face(library, font.string().c_str(), 0, &face)) {

      TT_OS2 *font_table = (TT_OS2 *)FT_Get_Sfnt_Table(face, FT_SFNT_OS2);
      int weight;
      if (font_table && font_table->usWeightClass != 0)
        weight = font_table->usWeightClass;
      else
        weight = (face->style_flags & FT_STYLE_FLAG_BOLD) == FT_STYLE_FLAG_BOLD
                     ? 700
                     : 400;

      fontFaces.push_back({.name = face->family_name,
                           .style = face->style_name,
                           .weight = weight,
                           .file = font.string()});
      FT_Done_Face(face);
    }
  }

  return fontFaces;
}

struct UIData {
  int daemonEnabled; // 0 = disabled, 1 = enabled
  goodnight::Daemon::Config config{
      .wakeLog = true,
  };
  std::vector<std::string> wakeupActions;
  bool english = false;
  bool runOnStartup = false;
} uiData;

static std::unique_ptr<goodnight::Daemon> daemon;
static Rml::Context *context;
static HWND hWnd = nullptr;

struct FileDeleter {
  void operator()(FILE *fp) const noexcept {
    if (fp) {
      _pclose(fp);
    }
  }
};

std::expected<std::pair<std::string, uint32_t>, std::error_code>
ExecCmd(const std::string &cmd) {
  std::unique_ptr<FILE, FileDeleter> pipe(_popen(cmd.c_str(), "r"));

  if (!pipe) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }

  std::array<char, 128> buffer;
  std::string result;

  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }

  int returnCode = _pclose(pipe.release());
  if (returnCode == -1) {
    return std::unexpected(std::error_code(errno, std::system_category()));
  }
  goodnight::Logger::info("Executed command: {}->{}", cmd, result);
  return std::make_pair(result, static_cast<uint32_t>(returnCode));
}

bool hasCreatedStartupTask() {
  return ExecCmd(
             R"(cmd /c schtasks /query /tn "GoodnightDaemon">nul && echo success")")
      ->first.contains("success");
}

bool createStartupTask(std::string path, std::string argument) {
  return ExecCmd((R"(cmd /c schtasks /create /tn "GoodnightDaemon" /tr ")" +
                  path + R"(" /sc onlogon /rl highest /f>nul && echo success)")
                     .c_str())
      ->first.contains("success");
}

bool deleteStartupTask() {
  return ExecCmd(
             R"(cmd /c schtasks /delete /tn "GoodnightDaemon" /f>nul && echo success)")
      ->first.contains("success");
}

static auto createMainModel(Rml::Context *context) {
  auto model = context->CreateDataModel("Goodnight");
  model.Bind("daemonEnabled", &uiData.daemonEnabled);
  model.Bind("disableDevices", &uiData.config.disableDevices);
  model.Bind("keepSleep", &uiData.config.keepSleep);
  model.Bind("suspendProcesses", &uiData.config.suspendProcesses);
  model.Bind("english", &uiData.english);
  model.Bind("runOnStartup", &uiData.runOnStartup);

  auto bindWakeBy = [&](auto action, auto string) {
    model.BindFunc(
        string,
        [=](auto &variant) {
          variant = std::ranges::contains(uiData.config.wakeupActions, action);
        },
        [=](const auto &variant) {
          goodnight::Logger::info("Set wakeup action: {}->{}", string,
                                  variant.template Get<bool>());
          if (variant.template Get<bool>()) {
            uiData.config.wakeupActions.insert(action);
          } else {
            uiData.config.wakeupActions.erase(action);
          }
          return Rml::Variant();
        });
  };

  using WA = goodnight::Daemon::Config::WakeupActions;
  bindWakeBy(WA::DisplayOn, "wakeDisplayOn");
  bindWakeBy(WA::Keyboard, "wakeKeyboard");
  bindWakeBy(WA::Mouse, "wakeMouse");
  bindWakeBy(WA::TouchPad, "wakeTouchPad");
  bindWakeBy(WA::Other, "wakeOther");

  model.BindEventCallback(
      "reloadConfigs", [](auto handle, auto &event, const auto variant) {
        if (!daemon)
          return Rml::Variant("Daemon not running");
        if (auto res = daemon->updateConfig(uiData.config); !res) {
          goodnight::Logger::error("Failed to update config: {}", res.error());

          return Rml::Variant(res.error());
        }
        return Rml::Variant();
      });

  model.BindEventCallback("switchDaemon", [](auto handle, auto &event,
                                             const auto variant) {
    bool enabled = variant[0].template Get<bool>();
    if (enabled) {
      if (daemon) {
        goodnight::Logger::error("Daemon already running");
        return Rml::Variant("Daemon already running");
      }
      daemon = std::make_unique<goodnight::Daemon>();
      if (auto res = daemon->updateConfig(uiData.config); !res) {
        goodnight::Logger::error("Failed to update config: {}", res.error());
        daemon = nullptr;
        return Rml::Variant(res.error());
      }
      uiData.daemonEnabled = 1;
    } else {
      daemon = nullptr;
      uiData.daemonEnabled = 0;
    }
    return Rml::Variant();
  });

  model.BindEventCallback(
      "openGithub", [](auto handle, auto &event, const auto variant) {
        ShellExecuteA(NULL, "open",
                      "https://github.com/std-microblock/Goodnight.Laptop",
                      NULL, NULL, SW_SHOWNORMAL);
      });

  model.BindEventCallback(
      "resizeWin", [](auto handle, auto &event, const auto variant) {
        auto width = variant[0].template Get<int>();
        auto height = variant[1].template Get<int>();
        auto ctx = glfwGetCurrentContext();
        auto scaleX = 1.0f, scaleY = 1.0f;
        glfwGetWindowContentScale(ctx, &scaleX, &scaleY);
        width *= scaleX;
        height *= scaleY;
        glfwSetWindowSize(glfwGetCurrentContext(), width, height);
      });

  model.BindEventCallback(
      "setStartup", [](auto handle, auto &event, const auto variant) {
        auto enabled = variant[0].template Get<bool>();
        if (enabled) {
          if (!hasCreatedStartupTask()) {
            if (!createStartupTask(__argv[0], "")) {
              goodnight::Logger::error("Failed to create startup task");
              return Rml::Variant("Failed to create startup task");
            } else {
              uiData.runOnStartup = true;
            }
          }
        } else {
          if (!deleteStartupTask()) {
            goodnight::Logger::error("Failed to delete startup task");
            return Rml::Variant("Failed to delete startup task");
          } else {
            uiData.runOnStartup = false;
          }
        }
        return Rml::Variant();
      });

  constexpr auto awayModeReg =
      "SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\238C9FA8-0AAD-"
      "41ED-83F4-97BE242C8F20\\25DFA149-5DD1-4736-B5AB-E8A37B5B8187";
  auto getAwayMode = []() {
    DWORD attributes;
    DWORD size = sizeof(attributes);
    if (RegGetValueA(HKEY_LOCAL_MACHINE, awayModeReg, "Attributes",
                     RRF_RT_REG_DWORD, NULL, &attributes,
                     &size) == ERROR_SUCCESS) {
      return (attributes & 2) == 2;
    }
    return false;
  };

  auto setAwayMode = [](bool enabled) {
    DWORD attributes = enabled ? 2 : 0;
    if (RegSetKeyValueA(HKEY_LOCAL_MACHINE, awayModeReg, "Attributes",
                        REG_DWORD, &attributes,
                        sizeof(attributes)) != ERROR_SUCCESS) {
      return false;
    }
    return true;
  };

  static bool awayModeDisabled = getAwayMode();
  model.BindFunc(
      "awayModeDisabled", [=](auto &variant) { variant = awayModeDisabled; },
      [=](const auto &variant) {
        if (auto res = setAwayMode(variant.template Get<bool>()); !res) {
          goodnight::Logger::error("Failed to set away mode: {}", res);
          return Rml::Variant(res);
        }
        return Rml::Variant();
      });

  return model;
}

int GetWindowDecoSupport() {
  OSVERSIONINFOEXW osvi;
  memset(&osvi, 0, sizeof(OSVERSIONINFOEXW));
  osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
  return 1;

  if (osvi.dwBuildNumber >= 17763)
    return 1; // Supports Windows 10 immersive dark mode (19), supports = 1
  if (osvi.dwBuildNumber >= 18985)
    return 2; // Supports Windows 10 immersive dark mode (20), supports = 2
}

void requireAdmin(char *argv[]) {
  if (!goodnight::isAdministrator()) {
    goodnight::Logger::error("Please run as administrator");
    ShellExecuteA(NULL, "runas", argv[0], NULL, NULL, SW_SHOWNORMAL);
    exit(1);
  }
}

std::expected<void, std::string> showUI() {
  constexpr int window_width = 390;
  constexpr int window_height = 600;

  if (!Backend::Initialize("Goodnight.", window_width, window_height, false)) {
    Rml::Shutdown();
    return std::unexpected("Failed to initialize backend");
  }

  // Get the GLFW window handle
  auto glfwWindow = glfwGetCurrentContext();
  hWnd = glfwGetWin32Window(glfwWindow);
  auto ico = LoadIcon(GetModuleHandle(NULL), "IDI_ICON1");
  if (!ico) {
    goodnight::Logger::error("Failed to load icon: {}", GetLastError());
  }
  SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)ico);

  int dwmUseDarkMode = 1;
  DwmSetWindowAttribute(
      hWnd,
      GetWindowDecoSupport() >= 2
          ? 20
          :   // DWMWINDOWATTRIBUTE::DWMWA_USE_IMMERSIVE_DARK_MODE
              // = 20 (starting from 18985)
          19, // DWMWINDOWATTRIBUTE::DWMWA_USE_IMMERSIVE_DARK_MODE
              // = 19 (before 18985),
      &dwmUseDarkMode, sizeof(dwmUseDarkMode));
  auto color = 0x005B3641;
  DwmSetWindowAttribute(hWnd,
                        34, // DWMWINDOWATTRIBUTE::DWMWA_BORDER_COLOR
                        &color, sizeof(color));
  color = 0x0045041C;
  DwmSetWindowAttribute(hWnd,
                        35, // DWMWINDOWATTRIBUTE::DWMWA_CAPTION_COLOR
                        &color, sizeof(color));
  color = 0x00FFFFFF;
  DwmSetWindowAttribute(hWnd,
                        36, // DWMWINDOWATTRIBUTE::DWMWA_TEXT_COLOR
                        &color, sizeof(color));

  SysInterf interf;
  Rml::SetSystemInterface(&interf);
  Rml::SetRenderInterface(Backend::GetRenderInterface());

  Rml::Initialise();

  static auto fonts = getFontFaces();
  auto loadFonts = [&](std::initializer_list<std::string> preferedFonts,
                       bool fallback, bool onlyOne = true) {
    for (auto &preferedFont : preferedFonts) {
      auto font = std::find_if(fonts.begin(), fonts.end(), [&](auto &font) {
        return font.name == preferedFont && font.weight == 400;
      });

      if (font != fonts.end()) {
        Rml::LoadFontFace(font->file, fallback);
        if (onlyOne)
          return;
      }
    }
  };

  context =
      Rml::CreateContext("main", Rml::Vector2i(window_width, window_height));
  if (!context) {
    Rml::Shutdown();
    Backend::Shutdown();
    return std::unexpected("Failed to create context");
  }

  auto model = createMainModel(context);
  auto handle = model.GetModelHandle();

  loadFonts(
      {
          "Arial",
      },
      false);

  loadFonts(
      {
          "Noto Sans SC",
          "Microsoft YaHei",
          "Segoe UI",
      },
      true);

  if constexpr (development)
    Rml::Debugger::Initialise(context);

  std::atomic_bool reload = false;
  constexpr auto devDocumentPath =
      R"(J:\Projects\GoodnightLaptop\lib\gui\gui.html)";

  Rml::ElementDocument *document;
  if constexpr (development) {
    document = context->LoadDocument(devDocumentPath);

    new filewatch::FileWatch<std::string>(
        devDocumentPath,
        [&](const std::string &path, const filewatch::Event change_type) {
          reload = true;
        });
  } else {
    document = context->LoadDocumentFromMemory(
#include "gui.html"
    );
  }

  if (!document) {
    context->UnloadAllDocuments();
    Rml::Shutdown();
    Backend::Shutdown();
    return std::unexpected("Failed to load document");
  }
  document->Show();

  while (Backend::ProcessEvents(context)) {
    context->Update();
    Backend::BeginFrame();
    context->Render();
    Backend::PresentFrame();
    if constexpr (development) {
      if (reload) {
        std::ifstream ifs(devDocumentPath);
        std::stringstream ss;
        ss << ifs.rdbuf();

        document->Close();
        document = context->LoadDocument(devDocumentPath);
        document->Show();
        goodnight::Logger::info("Reloaded!");
        reload = false;
      }
    }

    handle.DirtyAllVariables();
  }

  // Shutdown RmlUi.
  context->UnloadAllDocuments();
  Rml::Shutdown();
  Backend::Shutdown();
  context = nullptr;
  return {};
}

// int APIENTRY WinMain(HINSTANCE /*instance_handle*/,
//                      HINSTANCE /*previous_instance_handle*/,
//                      char * /*command_line*/, int /*command_show*/) {
int main(int argc, char *argv[]) {
  freopen("CONOUT$", "w", stdout);
  freopen("CONOUT$", "w", stderr);
  requireAdmin(argv);

  auto wakeUpEvent =
      CreateEventA(NULL, FALSE, FALSE, "Global\\GoodnightGUIEvent");
  if (wakeUpEvent == NULL) {
    goodnight::Logger::error("Failed to create wake up event: {}",
                             GetLastError());
    return 1;
  }

  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    goodnight::Logger::error("Another instance of the GUI is already running");
    wakeUpEvent =
        OpenEventA(EVENT_MODIFY_STATE, FALSE, "Global\\GoodnightGUIEvent");
    if (wakeUpEvent == NULL) {
      goodnight::Logger::error("Failed to open wake up event: {}",
                               GetLastError());
      return 1;
    }

    if (!SetEvent(wakeUpEvent)) {
      goodnight::Logger::error("Failed to set wake up event: {}",
                               GetLastError());
      return 1;
    }
    return 1;
  }

  if (argc > 1) {
    goodnight::Logger::info("Running in console mode");
  } else {
    LANGID langId = GetSystemDefaultLangID();
    uiData.english = PRIMARYLANGID(langId) != LANG_CHINESE;
    std::thread([]() { showUI(); }).detach();
    uiData.runOnStartup = hasCreatedStartupTask();
  }

  daemon = std::make_unique<goodnight::Daemon>();
  if (auto res = daemon->updateConfig(uiData.config); !res) {
    goodnight::Logger::error("Failed to update config: {}", res.error());
    daemon = nullptr;
  }
  uiData.daemonEnabled = 1;

  while (WaitForSingleObject(wakeUpEvent, INFINITE) == WAIT_OBJECT_0) {
    if (context) {
      goodnight::Logger::info("bringing window to front");
      SetForegroundWindow(hWnd);
    } else {
      std::thread([]() { showUI(); }).detach();
    }
  }
  return 0;
}