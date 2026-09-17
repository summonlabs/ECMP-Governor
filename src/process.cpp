#include "ecmp/process.hpp"

#include <array>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace ecmp {

#ifdef _WIN32
namespace {

std::wstring widen(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int size = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                         static_cast<int>(text.size()), nullptr, 0);
  std::wstring wide(static_cast<std::size_t>(size), L'\0');
  (void)::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                              wide.data(), size);
  return wide;
}

// Windows command line quoting rules: an argument is wrapped in double quotes when
// it contains a space or a tab, and backslashes that precede a quote are doubled.
std::wstring quote_argument(const std::string& argument) {
  const bool needs_quotes =
      argument.empty() || argument.find_first_of(" \t\"") != std::string::npos;
  if (!needs_quotes) {
    return widen(argument);
  }
  std::wstring out;
  out.push_back(L'"');
  std::size_t backslashes = 0;
  for (const char character : argument) {
    if (character == '\\') {
      ++backslashes;
      continue;
    }
    if (character == '"') {
      out.append(backslashes * 2 + 1, L'\\');
      out.push_back(L'"');
      backslashes = 0;
      continue;
    }
    out.append(backslashes, L'\\');
    backslashes = 0;
    out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(character)));
  }
  out.append(backslashes * 2, L'\\');
  out.push_back(L'"');
  return out;
}

}  // namespace
#endif

struct LocalProcess::Impl {
#ifdef _WIN32
  HANDLE process = nullptr;
  HANDLE thread = nullptr;
  HANDLE read_pipe = nullptr;
  HANDLE nul_stdin = nullptr;
  std::uint64_t pid = 0;
  bool exited = false;
  int exit_code = 0;
  std::string buffer;
  bool eof = false;
#endif
};

LocalProcess::LocalProcess() : impl_(std::make_unique<Impl>()) {}

LocalProcess::~LocalProcess() {
#ifdef _WIN32
  if (impl_) {
    if (impl_->read_pipe != nullptr) {
      ::CloseHandle(impl_->read_pipe);
    }
    if (impl_->nul_stdin != nullptr) {
      ::CloseHandle(impl_->nul_stdin);
    }
    if (impl_->thread != nullptr) {
      ::CloseHandle(impl_->thread);
    }
    if (impl_->process != nullptr) {
      if (!impl_->exited) {
        (void)::TerminateProcess(impl_->process, 1);
        (void)::WaitForSingleObject(impl_->process, INFINITE);
      }
      ::CloseHandle(impl_->process);
    }
  }
#endif
}

LocalProcess::LocalProcess(LocalProcess&& other) noexcept : impl_(std::move(other.impl_)) {}

LocalProcess& LocalProcess::operator=(LocalProcess&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}

std::optional<LocalProcess> LocalProcess::spawn(const Options& options, std::string& error) {
#ifdef _WIN32
  if (options.executable.empty()) {
    error = "no executable";
    return std::nullopt;
  }
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  HANDLE read_pipe = nullptr;
  HANDLE write_pipe = nullptr;
  if (::CreatePipe(&read_pipe, &write_pipe, &attributes, 0) == FALSE) {
    error = "CreatePipe failed";
    return std::nullopt;
  }
  (void)::SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

  SECURITY_ATTRIBUTES nul_attributes{};
  nul_attributes.nLength = sizeof(nul_attributes);
  nul_attributes.bInheritHandle = TRUE;
  const HANDLE nul_stdin =
      ::CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &nul_attributes,
                    OPEN_EXISTING, 0, nullptr);

  std::wstring command_line = quote_argument(options.executable);
  for (const std::string& argument : options.arguments) {
    command_line.push_back(L' ');
    command_line += quote_argument(argument);
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write_pipe;
  startup.hStdError = write_pipe;
  startup.hStdInput = nul_stdin;
  PROCESS_INFORMATION information{};
  const std::wstring working_directory = widen(options.working_directory);
  const BOOL created = ::CreateProcessW(
      nullptr, command_line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
      working_directory.empty() ? nullptr : working_directory.c_str(), &startup, &information);
  (void)::CloseHandle(write_pipe);
  if (created == FALSE) {
    error = "CreateProcess failed with error " + std::to_string(::GetLastError());
    (void)::CloseHandle(read_pipe);
    if (nul_stdin != INVALID_HANDLE_VALUE) {
      (void)::CloseHandle(nul_stdin);
    }
    return std::nullopt;
  }
  LocalProcess process;
  process.impl_->process = information.hProcess;
  process.impl_->thread = information.hThread;
  process.impl_->read_pipe = read_pipe;
  process.impl_->nul_stdin = nul_stdin == INVALID_HANDLE_VALUE ? nullptr : nul_stdin;
  process.impl_->pid = information.dwProcessId;
  return process;
#else
  (void)options;
  error = "local process supervision is implemented for Windows in 1.0.0";
  return std::nullopt;
#endif
}

bool LocalProcess::valid() const noexcept {
#ifdef _WIN32
  return impl_ && impl_->process != nullptr;
#else
  return false;
#endif
}

std::uint64_t LocalProcess::pid() const noexcept {
#ifdef _WIN32
  return impl_ ? impl_->pid : 0;
#else
  return 0;
#endif
}

bool LocalProcess::running() const {
#ifdef _WIN32
  if (!valid() || impl_->exited) {
    return false;
  }
  return ::WaitForSingleObject(impl_->process, 0) == WAIT_TIMEOUT;
#else
  return false;
#endif
}

bool LocalProcess::read_line(std::string& line) {
#ifdef _WIN32
  if (!impl_ || impl_->read_pipe == nullptr) {
    return false;
  }
  for (;;) {
    const std::size_t newline = impl_->buffer.find('\n');
    if (newline != std::string::npos) {
      line = impl_->buffer.substr(0, newline);
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      impl_->buffer.erase(0, newline + 1);
      return true;
    }
    if (impl_->eof) {
      if (impl_->buffer.empty()) {
        return false;
      }
      line = impl_->buffer;
      impl_->buffer.clear();
      return true;
    }
    std::array<char, 4096> chunk{};
    DWORD read = 0;
    if (::ReadFile(impl_->read_pipe, chunk.data(), static_cast<DWORD>(chunk.size()), &read,
                   nullptr) == FALSE ||
        read == 0) {
      impl_->eof = true;
      continue;
    }
    impl_->buffer.append(chunk.data(), read);
  }
#else
  (void)line;
  return false;
#endif
}

std::string LocalProcess::read_until_exit() {
  std::string out;
  std::string line;
  while (read_line(line)) {
    out += line;
    out += '\n';
  }
  return out;
}

int LocalProcess::wait_for_exit() {
#ifdef _WIN32
  if (!valid()) {
    return -1;
  }
  (void)::WaitForSingleObject(impl_->process, INFINITE);
  DWORD code = 0;
  (void)::GetExitCodeProcess(impl_->process, &code);
  impl_->exited = true;
  impl_->exit_code = static_cast<int>(code);
  return impl_->exit_code;
#else
  return -1;
#endif
}

bool LocalProcess::terminate() {
#ifdef _WIN32
  if (!valid() || impl_->exited || !running()) {
    return false;
  }
  if (::TerminateProcess(impl_->process, 9) == FALSE) {
    return false;
  }
  (void)::WaitForSingleObject(impl_->process, INFINITE);
  DWORD code = 0;
  (void)::GetExitCodeProcess(impl_->process, &code);
  impl_->exited = true;
  impl_->exit_code = static_cast<int>(code);
  return true;
#else
  return false;
#endif
}

}  // namespace ecmp
