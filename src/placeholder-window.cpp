#include "goodnight/placeholder-window.h"

#include "Windows.h"
#include <cstdint>
#include <unordered_map>

namespace goodnight {
static std::unordered_map<HWND, PlaceholderWindow::WndProc>
    windowProcs;
PlaceholderWindow::PlaceholderWindow() {
  constexpr char class_name[] = "PlaceholderWindowClass";

  WNDCLASS wc = {};
  wc.hInstance = GetModuleHandle(NULL);
  wc.lpszClassName = class_name;
  wc.lpfnWndProc = [](HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (windowProcs.contains(hWnd)) {
      windowProcs[hWnd](hWnd, message, wParam, lParam);
    }
    return DefWindowProc(hWnd, message, wParam, lParam);
  };

  RegisterClass(&wc);
  hWnd =
      CreateWindowEx(0, class_name, "", WS_OVERLAPPEDWINDOW,

                     CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,

                     NULL, NULL, GetModuleHandle(NULL), NULL);
}

PlaceholderWindow::~PlaceholderWindow() {
  windowProcs.erase((HWND)hWnd);
  DestroyWindow((HWND)hWnd);
}

PlaceholderWindow::PlaceholderWindow(WndProc proc)
    : goodnight::PlaceholderWindow() {
  windowProcs[(HWND)hWnd] = proc;
}
} // namespace goodnight