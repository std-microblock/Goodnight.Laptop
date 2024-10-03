#include "goodnight/placeholder-window.h"

#include "Windows.h"

namespace goodnight {
PlaceholderWindow::PlaceholderWindow() {
  constexpr char class_name[] = "PlaceholderWindowClass";

  WNDCLASS wc = {};
  wc.lpfnWndProc = DefWindowProc;
  wc.hInstance = GetModuleHandle(NULL);
  wc.lpszClassName = class_name;

  RegisterClass(&wc);
  hWnd =
      CreateWindowEx(0, class_name, "", WS_OVERLAPPEDWINDOW,

                     CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,

                     NULL, NULL, GetModuleHandle(NULL), NULL);
}

PlaceholderWindow::~PlaceholderWindow() { DestroyWindow((HWND)hWnd); }
} // namespace goodnight