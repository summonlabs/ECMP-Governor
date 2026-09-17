#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ecmp/limits.hpp"
#include "ecmp/protocol.hpp"

namespace ecmp {

// Outcome of a bounded protocol read.  A peer that sends a partial frame cannot
// pin a session forever: the read fails with an explicit structured status.
enum class ReceiveStatus : std::uint32_t {
  OK = 0,
  TIMEOUT = 1,
  CLOSED = 2,
  FAILURE = 3,
};

[[nodiscard]] std::string_view to_string(ReceiveStatus status) noexcept;

// Loopback-capable TCP connection.  Platform support: Windows 1.0.0.
class TcpConnection {
 public:
  TcpConnection();
  ~TcpConnection();
  TcpConnection(TcpConnection&& other) noexcept;
  TcpConnection& operator=(TcpConnection&& other) noexcept;
  TcpConnection(const TcpConnection&) = delete;
  TcpConnection& operator=(const TcpConnection&) = delete;

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] bool send_all(std::span<const std::uint8_t> bytes, std::string& error);
  [[nodiscard]] ReceiveStatus receive_exactly(std::span<std::uint8_t> out,
                                              std::uint32_t deadline_ms, std::string& error);
  // Cancels a blocking read from another thread and releases the socket.
  void shutdown();
  void close();
  [[nodiscard]] std::uint16_t local_port() const;
  [[nodiscard]] std::uint16_t remote_port() const;

 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;
  friend class TcpListener;
  friend std::optional<TcpConnection> connect_loopback(std::uint16_t port, std::string& error);
};

class TcpListener {
 public:
  TcpListener();
  ~TcpListener();
  TcpListener(TcpListener&& other) noexcept;
  TcpListener& operator=(TcpListener&& other) noexcept;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  // Binds to the loopback interface.  Port 0 selects an ephemeral port, which is
  // what every test and example uses: ECMP Governor never relies on a fixed port.
  [[nodiscard]] static std::optional<TcpListener> bind_loopback(std::uint16_t port,
                                                               std::string& error);
  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::uint16_t port() const;
  [[nodiscard]] std::optional<TcpConnection> accept(std::string& error);
  void close();

 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;
};

[[nodiscard]] std::optional<TcpConnection> connect_loopback(std::uint16_t port,
                                                           std::string& error);

// Framed transport helpers.  `read_frame` reads exactly one frame using the
// declared frame length, rejects an over-long or malformed header before
// allocating anything, and fails with PEER_TIMEOUT when the peer stops mid-frame.
[[nodiscard]] WireDefect read_frame(TcpConnection& connection, const GovernorLimits& limits,
                                    std::uint32_t deadline_ms, Envelope& out, std::string& error);
[[nodiscard]] bool write_frame(TcpConnection& connection, const Envelope& envelope,
                               const GovernorLimits& limits, std::string& error);

}  // namespace ecmp
