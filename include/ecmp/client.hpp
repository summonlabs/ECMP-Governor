#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ecmp/governor.hpp"
#include "ecmp/net.hpp"
#include "ecmp/protocol.hpp"

namespace ecmp {

// Client session against one coordinator.  The session carries the live authority
// triple (epoch, publisher, worker boot) that every mutation binds.
class EcmpClient {
 public:
  EcmpClient();
  ~EcmpClient();
  EcmpClient(EcmpClient&& other) noexcept;
  EcmpClient& operator=(EcmpClient&& other) noexcept;
  EcmpClient(const EcmpClient&) = delete;
  EcmpClient& operator=(const EcmpClient&) = delete;

  [[nodiscard]] static std::optional<EcmpClient> connect(const std::string& host,
                                                        std::uint16_t port,
                                                        std::uint32_t deadline_ms,
                                                        std::string& error);

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] bool hello(HelloResponseBody& out, std::string& error);
  [[nodiscard]] bool register_publisher(const PublisherRegistration& registration,
                                        RegisterPublisherResponseBody& out, std::string& error);

  void set_epoch(CoordinatorEpoch epoch) noexcept;
  void set_publisher(PublisherId publisher) noexcept;
  void set_worker_boot(WorkerBootId boot) noexcept;
  void set_attempt(MutationAttemptId attempt) noexcept;
  [[nodiscard]] CoordinatorEpoch epoch() const noexcept;
  [[nodiscard]] PublisherId publisher() const noexcept;
  [[nodiscard]] WorkerBootId worker_boot() const noexcept;

  [[nodiscard]] bool create_group(const CreateGroupRequest& request, MutationResult& out,
                                  std::string& error);
  [[nodiscard]] bool add_member(const AddMemberRequest& request, MutationResult& out,
                                std::string& error);
  [[nodiscard]] bool remove_member(const RemoveMemberRequest& request, MutationResult& out,
                                   std::string& error);
  [[nodiscard]] bool set_member_enabled(const SetMemberEnabledRequest& request, MutationResult& out,
                                        std::string& error);
  [[nodiscard]] bool revalidate_group(const RevalidateGroupRequest& request, MutationResult& out,
                                      std::string& error);
  [[nodiscard]] bool plan_rebalance(const RebalancePlanRequest& request, MutationResult& out,
                                    std::string& error);
  [[nodiscard]] bool commit_rebalance(const RebalanceCommitRequest& request, MutationResult& out,
                                      std::string& error);
  [[nodiscard]] bool snapshot(const ECMPGroupId& group, SnapshotResponseBody& out,
                              std::string& error);
  [[nodiscard]] bool list_groups(ListGroupsResponseBody& out, std::string& error);
  [[nodiscard]] bool explain(const ExplainRequest& request, ExplainResponseBody& out,
                             std::string& error);
  [[nodiscard]] bool notify_path_authority_change(const PathAuthorityChangeNotice& notice,
                                                  MutationResult& out, std::string& error);

  // Blocks until the coordinator fences this session or the connection ends.
  // Returns true when a FENCE_NOTICE was received.  The read budget is unlimited
  // by design: a worker waits for an authoritative fence, it does not guess.
  [[nodiscard]] bool wait_for_fence(std::string& error);

  void close();

 private:
  [[nodiscard]] bool round_trip(WireMessageId request_id,
                                const std::vector<std::uint8_t>& payload,
                                WireMessageId expected, Envelope& response, std::string& error);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ecmp
