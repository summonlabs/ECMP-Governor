#include "ecmp/net.hpp"

#include <array>
#include <cstring>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
// ws2tcpip.h from the Windows SDK is the only source of the Code Analysis warning
// C6101 ("returning uninitialized memory '*Mtu'").  It is not reachable from
// first-party code, so the suppression is scoped to this external include alone;
// no first-party warning is suppressed anywhere.
#pragma warning(push)
#pragma warning(disable : 6101)
#include <ws2tcpip.h>
#pragma warning(pop)
#else
#error "ECMP Governor 1.0.0 transport is implemented for Windows"
#endif

#include "ecmp/bytes.hpp"
#include "ecmp/digest.hpp"

namespace ecmp {
namespace {

#ifdef _WIN32
struct WinsockGuard {
  WinsockGuard() {
    WSADATA data{};
    (void)WSAStartup(MAKEWORD(2, 2), &data);
  }
  ~WinsockGuard() { WSACleanup(); }
};

void ensure_winsock() {
  static WinsockGuard guard;
  (void)guard;
}

std::string socket_error_text(int code) {
  return "winsock error " + std::to_string(code);
}
#endif

}  // namespace

std::string_view to_string(ReceiveStatus status) noexcept {
  switch (status) {
    case ReceiveStatus::OK: return "OK";
    case ReceiveStatus::TIMEOUT: return "TIMEOUT";
    case ReceiveStatus::CLOSED: return "CLOSED";
    case ReceiveStatus::FAILURE: return "FAILURE";
  }
  return "UNKNOWN_RECEIVE_STATUS";
}

struct TcpConnection::Impl {
  std::uintptr_t socket = static_cast<std::uintptr_t>(~0ull);
  bool closed = false;
};

TcpConnection::TcpConnection() : impl_(std::make_shared<Impl>()) { ensure_winsock(); }

TcpConnection::~TcpConnection() { close(); }

TcpConnection::TcpConnection(TcpConnection&& other) noexcept : impl_(std::move(other.impl_)) {}

TcpConnection& TcpConnection::operator=(TcpConnection&& other) noexcept {
  if (this != &other) {
    close();
    impl_ = std::move(other.impl_);
  }
  return *this;
}

bool TcpConnection::valid() const noexcept {
  return impl_ && !impl_->closed && impl_->socket != static_cast<std::uintptr_t>(~0ull);
}

bool TcpConnection::send_all(std::span<const std::uint8_t> bytes, std::string& error) {
  if (!valid()) {
    error = "connection is not open";
    return false;
  }
  std::size_t sent = 0;
  while (sent < bytes.size()) {
    const int result = ::send(static_cast<SOCKET>(impl_->socket),
                              reinterpret_cast<const char*>(bytes.data() + sent),
                              static_cast<int>(bytes.size() - sent), 0);
    if (result == SOCKET_ERROR || result == 0) {
      error = socket_error_text(WSAGetLastError());
      return false;
    }
    sent += static_cast<std::size_t>(result);
  }
  return true;
}

ReceiveStatus TcpConnection::receive_exactly(std::span<std::uint8_t> out,
                                             std::uint32_t deadline_ms, std::string& error) {
  if (!valid()) {
    error = "connection is not open";
    return ReceiveStatus::FAILURE;
  }
  const std::uint64_t start = static_cast<std::uint64_t>(::GetTickCount64());
  std::size_t received = 0;
  while (received < out.size()) {
    if (deadline_ms > 0) {
      const std::uint64_t now = static_cast<std::uint64_t>(::GetTickCount64());
      const std::uint64_t elapsed = now - start;
      if (elapsed >= deadline_ms) {
        error = "peer did not complete the frame within the receive budget";
        return ReceiveStatus::TIMEOUT;
      }
      const std::uint64_t remaining = deadline_ms - elapsed;
      fd_set read_set;
      FD_ZERO(&read_set);
      FD_SET(static_cast<SOCKET>(impl_->socket), &read_set);
      timeval timeout{};
      timeout.tv_sec = static_cast<long>(remaining / 1000);
      timeout.tv_usec = static_cast<long>((remaining % 1000) * 1000);
      const int ready = ::select(0, &read_set, nullptr, nullptr, &timeout);
      if (ready == 0) {
        error = "peer did not complete the frame within the receive budget";
        return ReceiveStatus::TIMEOUT;
      }
      if (ready == SOCKET_ERROR) {
        error = socket_error_text(WSAGetLastError());
        return ReceiveStatus::FAILURE;
      }
    }
    const int result =
        ::recv(static_cast<SOCKET>(impl_->socket),
               reinterpret_cast<char*>(out.data() + received),
               static_cast<int>(out.size() - received), 0);
    if (result == 0) {
      error = "peer closed the connection";
      return ReceiveStatus::CLOSED;
    }
    if (result == SOCKET_ERROR) {
      error = socket_error_text(WSAGetLastError());
      return ReceiveStatus::FAILURE;
    }
    received += static_cast<std::size_t>(result);
  }
  return ReceiveStatus::OK;
}

void TcpConnection::shutdown() {
  if (!valid()) {
    return;
  }
  // shutdown() is what actually releases a thread blocked in recv() on Windows;
  // closesocket() alone can leave the blocked call pending.
  (void)::shutdown(static_cast<SOCKET>(impl_->socket), SD_BOTH);
}

void TcpConnection::close() {
  if (!impl_ || impl_->closed) {
    return;
  }
  impl_->closed = true;
  if (impl_->socket != static_cast<std::uintptr_t>(~0ull)) {
    (void)::closesocket(static_cast<SOCKET>(impl_->socket));
    impl_->socket = static_cast<std::uintptr_t>(~0ull);
  }
}

std::uint16_t TcpConnection::local_port() const {
  if (!valid()) {
    return 0;
  }
  sockaddr_in address{};
  int length = sizeof(address);
  if (::getsockname(static_cast<SOCKET>(impl_->socket), reinterpret_cast<sockaddr*>(&address),
                    &length) == SOCKET_ERROR) {
    return 0;
  }
  return ntohs(address.sin_port);
}

std::uint16_t TcpConnection::remote_port() const {
  if (!valid()) {
    return 0;
  }
  sockaddr_in address{};
  int length = sizeof(address);
  if (::getpeername(static_cast<SOCKET>(impl_->socket), reinterpret_cast<sockaddr*>(&address),
                    &length) == SOCKET_ERROR) {
    return 0;
  }
  return ntohs(address.sin_port);
}

struct TcpListener::Impl {
  std::uintptr_t socket = static_cast<std::uintptr_t>(~0ull);
  std::uint16_t port = 0;
};

TcpListener::TcpListener() : impl_(std::make_shared<Impl>()) { ensure_winsock(); }

TcpListener::~TcpListener() { close(); }

TcpListener::TcpListener(TcpListener&& other) noexcept : impl_(std::move(other.impl_)) {}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    close();
    impl_ = std::move(other.impl_);
  }
  return *this;
}

std::optional<TcpListener> TcpListener::bind_loopback(std::uint16_t port, std::string& error) {
  ensure_winsock();
  TcpListener listener;
  const SOCKET raw = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (raw == INVALID_SOCKET) {
    error = socket_error_text(WSAGetLastError());
    return std::nullopt;
  }
  const BOOL exclusive = TRUE;
  (void)::setsockopt(raw, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  if (::bind(raw, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
    error = socket_error_text(WSAGetLastError());
    (void)::closesocket(raw);
    return std::nullopt;
  }
  if (::listen(raw, SOMAXCONN) == SOCKET_ERROR) {
    error = socket_error_text(WSAGetLastError());
    (void)::closesocket(raw);
    return std::nullopt;
  }
  sockaddr_in bound{};
  int length = sizeof(bound);
  if (::getsockname(raw, reinterpret_cast<sockaddr*>(&bound), &length) == SOCKET_ERROR) {
    error = socket_error_text(WSAGetLastError());
    (void)::closesocket(raw);
    return std::nullopt;
  }
  listener.impl_->socket = static_cast<std::uintptr_t>(raw);
  listener.impl_->port = ntohs(bound.sin_port);
  return listener;
}

bool TcpListener::valid() const noexcept {
  return impl_ && impl_->socket != static_cast<std::uintptr_t>(~0ull);
}

std::uint16_t TcpListener::port() const { return impl_ ? impl_->port : 0; }

std::optional<TcpConnection> TcpListener::accept(std::string& error) {
  if (!valid()) {
    error = "listener is not open";
    return std::nullopt;
  }
  const SOCKET raw = ::accept(static_cast<SOCKET>(impl_->socket), nullptr, nullptr);
  if (raw == INVALID_SOCKET) {
    error = socket_error_text(WSAGetLastError());
    return std::nullopt;
  }
  TcpConnection connection;
  connection.impl_->socket = static_cast<std::uintptr_t>(raw);
  return connection;
}

void TcpListener::close() {
  if (!impl_ || impl_->socket == static_cast<std::uintptr_t>(~0ull)) {
    return;
  }
  (void)::closesocket(static_cast<SOCKET>(impl_->socket));
  impl_->socket = static_cast<std::uintptr_t>(~0ull);
}

std::optional<TcpConnection> connect_loopback(std::uint16_t port, std::string& error) {
  ensure_winsock();
  const SOCKET raw = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (raw == INVALID_SOCKET) {
    error = socket_error_text(WSAGetLastError());
    return std::nullopt;
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  if (::connect(raw, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
    error = socket_error_text(WSAGetLastError());
    (void)::closesocket(raw);
    return std::nullopt;
  }
  TcpConnection connection;
  connection.impl_->socket = static_cast<std::uintptr_t>(raw);
  return connection;
}

WireDefect read_frame(TcpConnection& connection, const GovernorLimits& limits,
                      std::uint32_t deadline_ms, Envelope& out, std::string& error) {
  std::array<std::uint8_t, kWireHeaderBytes> header{};
  ReceiveStatus status = connection.receive_exactly(header, deadline_ms, error);
  if (status == ReceiveStatus::TIMEOUT) {
    return WireDefect::PEER_TIMEOUT;
  }
  if (status == ReceiveStatus::CLOSED) {
    return WireDefect::PEER_CLOSED;
  }
  if (status != ReceiveStatus::OK) {
    return WireDefect::TRUNCATED;
  }
  Decoder decoder(std::span<const std::uint8_t>(header.data(), header.size()),
                  limits.max_frame_bytes);
  std::array<std::uint8_t, 4> magic{};
  if (!decoder.raw(magic)) {
    return WireDefect::TRUNCATED;
  }
  if (magic[0] != 'E' || magic[1] != 'C' || magic[2] != 'M' || magic[3] != 'P') {
    return WireDefect::BAD_MAGIC;
  }
  std::uint16_t version = 0;
  std::uint16_t message = 0;
  std::uint32_t flags = 0;
  std::uint32_t payload_length = 0;
  if (!decoder.u16(version) || !decoder.u16(message) || !decoder.u32(flags) ||
      !decoder.u32(payload_length)) {
    return WireDefect::TRUNCATED;
  }
  if (version != kWireVersion) {
    return WireDefect::VERSION_MISMATCH;
  }
  if (!is_known_message(message)) {
    return WireDefect::UNKNOWN_MESSAGE;
  }
  if (payload_length > limits.max_frame_bytes) {
    return WireDefect::FRAME_TOO_LARGE;
  }
  std::vector<std::uint8_t> frame(kWireHeaderBytes + payload_length + kWireTagBytes);
  std::memcpy(frame.data(), header.data(), header.size());
  const std::size_t remaining = frame.size() - kWireHeaderBytes;
  status = connection.receive_exactly(
      std::span<std::uint8_t>(frame.data() + kWireHeaderBytes, remaining), deadline_ms, error);
  if (status == ReceiveStatus::TIMEOUT) {
    return WireDefect::PEER_TIMEOUT;
  }
  if (status == ReceiveStatus::CLOSED) {
    return WireDefect::PEER_CLOSED;
  }
  if (status != ReceiveStatus::OK) {
    return WireDefect::TRUNCATED;
  }
  return decode_frame(frame, limits, out);
}

bool write_frame(TcpConnection& connection, const Envelope& envelope, const GovernorLimits& limits,
                 std::string& error) {
  const std::vector<std::uint8_t> frame = encode_frame(envelope, limits);
  if (frame.empty()) {
    error = "frame exceeds the configured bound";
    return false;
  }
  return connection.send_all(frame, error);
}

}  // namespace ecmp
