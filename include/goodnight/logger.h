#include <chrono>
#include <format>
#include <iostream>
#include <print>

namespace goodnight {
enum class LogLevel { DEBUG, INFO, ERROR };
extern LogLevel logLevel;

struct Logger {
  static auto time() {
    auto timestamp = std::chrono::system_clock::now();

    std::time_t now_tt = std::chrono::system_clock::to_time_t(timestamp);
    const auto now = std::chrono::system_clock::now();
    const auto time_zone = std::chrono::current_zone();
    const auto local_time = time_zone->to_local(now);
    const auto time_point =
        std::chrono::time_point_cast<std::chrono::days>(local_time);
    const auto year_month_day = std::chrono::year_month_day{time_point};
    const auto time_of_day = std::chrono::hh_mm_ss{local_time - time_point};

    return std::format("{:%Y-%m-%d %H:%M:%S}", local_time);
  }

  template <typename... Items>
  static void debug(const std::format_string<Items...> fmt, Items &&...items) {
    if (logLevel > LogLevel::DEBUG)
      return;
  
    auto log = std::format(fmt, std::forward<Items>(items)...);
    std::print("[D][{}] {}\n", time(), log);
  }

  template <typename... Items>
  static void info(const std::format_string<Items...> fmt, Items &&...items) {
    if (logLevel > LogLevel::INFO)
      return;
    auto log = std::format(fmt, std::forward<Items>(items)...);
    std::print("[I][{}] {}\n", time(), log);
  }

  template <typename... Items>
  static void error(const std::format_string<Items...> fmt, Items &&...items) {
    if (logLevel > LogLevel::ERROR)
      return;
    auto log = std::format(fmt, std::forward<Items>(items)...);
    std::print(std::cerr, "[E][{}] {}\n", time(), log);
  }
};

} // namespace goodnight