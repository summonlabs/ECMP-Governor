#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ecmp/governor.hpp"
#include "ecmp/net.hpp"

namespace ecmp {

// Seam between the coordinator and the upstream domains it does not own.  The
// coordinator applies an upstream fact to its own observation view before the
// governor re-observes, so the governor always reacts to an observation and never
// to a bare claim.
class UpstreamNoticeHook {
 public:
  UpstreamNoticeHook() = default;
  virtual ~UpstreamNoticeHook() = default;
  UpstreamNoticeHook(const UpstreamNoticeHook&) = delete;
  UpstreamNoticeHook& operator=(const UpstreamNoticeHook&) = delete;

  virtual void on_path_authority_change(const PathAuthorityChangeNotice& notice) = 0;
  virtual void on_multipath_set_change(const MultipathSetChangeNotice& notice) = 0;
  virtual void on_cost_generation_change(const CostGenerationChangeNotice& notice) = 0;
};

struct CoordinatorServerOptions {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;
  // Bounded protocol read budget for one frame.  A peer that stops mid-frame is
  // disconnected with an explicit PEER_TIMEOUT failure instead of pinning a
  // session.
  std::uint32_t receive_deadline_ms = 5000;
  GovernorLimits limits;
  std::filesystem::path store_path;  // empty disables durable autosave
  bool autosave = true;
  UpstreamNoticeHook* upstream_hook = nullptr;
  // 0 means "serve until stopped"; a positive value stops the coordinator after
  // that many handled requests, which the scripted examples and proofs use.
  std::uint64_t max_requests = 0;
};

// Single authoritative coordinator.  ECMP Governor 1.0.0 is not a consensus
// system: exactly one coordinator owns the durable store at a time and stale
// epochs are fenced by epoch comparison, not by distributed agreement.
class CoordinatorServer {
 public:
  CoordinatorServer(EcmpGovernor& governor, CoordinatorServerOptions options);
  ~CoordinatorServer();
  CoordinatorServer(const CoordinatorServer&) = delete;
  CoordinatorServer& operator=(const CoordinatorServer&) = delete;

  [[nodiscard]] bool start(std::string& error);
  [[nodiscard]] std::uint16_t port() const;
  void serve();  // accept loop until stop() is called
  void stop();
  [[nodiscard]] std::uint32_t active_sessions() const;
  [[nodiscard]] std::uint64_t handled_requests() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ecmp
