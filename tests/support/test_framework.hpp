#pragma once

// Minimal deterministic test framework for ECMP Governor.
//
// There are no timeouts anywhere in this suite: a hanging test is a defect, not
// something to hide behind a watchdog.  Every test either completes or the
// process does not finish, which is reported as a failure by the caller.

#include <cstdint>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace ecmp::test {

inline int g_failures = 0;
inline int g_checks = 0;
inline std::string g_current;

class TestFailure : public std::exception {
 public:
  explicit TestFailure(std::string message) : message_(std::move(message)) {}
  [[nodiscard]] const char* what() const noexcept override { return message_.c_str(); }

 private:
  std::string message_;
};

struct TestCase {
  std::string name;
  void (*body)();
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

struct Registrar {
  Registrar(const char* name, void (*body)()) { registry().push_back(TestCase{name, body}); }
};

inline void report_failure(const char* file, int line, const std::string& message) {
  ++g_failures;
  std::cout << "FAIL " << g_current << " " << file << ":" << line << ": " << message << "\n";
}

template <class T>
std::string stringify(const T& value) {
  if constexpr (requires(std::ostream& stream, const T& item) { stream << item; }) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else if constexpr (requires(const T& item) { item.to_text(); }) {
    return value.to_text();
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<std::uint64_t>(value));
  } else {
    return "<value>";
  }
}

inline std::string stringify(bool value) { return value ? "true" : "false"; }

inline int run_all(const char* suite) {
  std::cout << "suite " << suite << " tests=" << registry().size() << "\n";
  for (const TestCase& test : registry()) {
    g_current = test.name;
    const int failures_before = g_failures;
    try {
      test.body();
    } catch (const TestFailure& failure) {
      report_failure(__FILE__, 0, failure.what());
    } catch (const std::exception& error) {
      report_failure(__FILE__, 0, std::string("unexpected exception: ") + error.what());
    } catch (...) {
      report_failure(__FILE__, 0, "unexpected non-standard exception");
    }
    if (g_failures == failures_before) {
      std::cout << "PASS " << test.name << "\n";
    }
  }
  std::cout << "summary suite=" << suite << " tests=" << registry().size()
            << " checks=" << g_checks << " failures=" << g_failures << "\n";
  return g_failures == 0 ? 0 : 1;
}

}  // namespace ecmp::test

#define ECMP_TEST(name)                                                     \
  static void name();                                                       \
  static const ::ecmp::test::Registrar ecmp_test_registrar_##name(#name,    \
                                                                  name);    \
  static void name()

#define ECMP_CHECK(condition)                                                       \
  do {                                                                              \
    ++::ecmp::test::g_checks;                                                       \
    if (!(condition)) {                                                             \
      ::ecmp::test::report_failure(__FILE__, __LINE__, "check failed: " #condition); \
    }                                                                               \
  } while (false)

#define ECMP_CHECK_EQ(actual, expected)                                                    \
  do {                                                                                     \
    ++::ecmp::test::g_checks;                                                              \
    const auto& ecmp_actual = (actual);                                                    \
    const auto& ecmp_expected = (expected);                                                \
    if (!(ecmp_actual == ecmp_expected)) {                                                 \
      ::ecmp::test::report_failure(__FILE__, __LINE__,                                     \
                                   "expected " #actual " == " #expected " but got " +      \
                                       ::ecmp::test::stringify(ecmp_actual) + " vs " +     \
                                       ::ecmp::test::stringify(ecmp_expected));            \
    }                                                                                      \
  } while (false)

#define ECMP_REQUIRE(condition)                                                     \
  do {                                                                              \
    ++::ecmp::test::g_checks;                                                       \
    if (!(condition)) {                                                             \
      throw ::ecmp::test::TestFailure(std::string(__FILE__) + ":" +                 \
                                      std::to_string(__LINE__) +                    \
                                      " requirement failed: " #condition);          \
    }                                                                               \
  } while (false)
