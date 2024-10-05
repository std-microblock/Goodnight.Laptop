#pragma once

#include <cstdint>
#include <functional>
namespace goodnight {
struct PlaceholderWindow {
  void* hWnd;
  using WndProc = std::function<void(void *, size_t, unsigned long long, long long)>;
  PlaceholderWindow(WndProc proc);
  PlaceholderWindow();
  ~PlaceholderWindow();
};
} // namespace goodnight