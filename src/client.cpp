#include "ecmp/client.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <utility>
#include <vector>

#include "ecmp/bytes.hpp"
#include "ecmp/digest.hpp"

namespace ecmp {
namespace {

MutationAttemptId derive_attempt(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                 std::uint64_t counter) {
  Encoder encoder;
  encoder.raw(publisher.bytes());
  encoder.raw(worker_boot.bytes());
  encoder.u64(counter);
  const Digest digest = domain_digest("ecmp.client.attempt.v1", encoder.bytes());
  std::array<std::uint8_t, 16> raw{};
  std::copy(digest.bytes().begin(), digest.bytes().begin() + 16, raw.begin());
  return MutationAttemptId::from_bytes(raw);
}

}  // namespace

struct EcmpClient::Impl {
  TcpConnection connection;
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  MutationAttemptId pinned_attempt;
  GovernorLimits limits;
  std::uint32_t deadline_ms = 5000;
  std::uint64_t counter = 0;
  bool connected = false;

  [[nodiscard]] MutationAttemptId next_attempt() {
    if (!pinned_attempt.is_nil()) {
      return pinned_attempt;
    }
    ++counter;
    return derive_attempt(publisher, worker_boot, counter);
  }
};

EcmpClient::EcmpClient() : impl_(std::make_unique<Impl>()) {}

EcmpClient::~EcmpClient() = default;

EcmpClient::EcmpClient(EcmpClient&& other) noexcept : impl_(std::move(other.impl_)) {}

EcmpClient& EcmpClient::operator=(EcmpClient&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}

std::optional<EcmpClient> EcmpClient::connect(const std::string& host, std::uint16_t port,
                                              std::uint32_t deadline_ms, std::string& error) {
  (void)host;
  std::optional<TcpConnection> connection = connect_loopback(port, error);
  if (!connection.has_value()) {
    return std::nullopt;
  }
  EcmpClient client;
  client.impl_->connection = std::move(*connection);
  client.impl_->deadline_ms = deadline_ms;
  client.impl_->connected = true;
  return client;
}

bool EcmpClient::valid() const noexcept { return impl_ && impl_->connected; }

void EcmpClient::set_epoch(CoordinatorEpoch epoch) noexcept {
  impl_->epoch = epoch;
}

void EcmpClient::set_publisher(PublisherId publisher) noexcept {
  impl_->publisher = publisher;
}

void EcmpClient::set_worker_boot(WorkerBootId boot) noexcept { impl_->worker_boot = boot; }

void EcmpClient::set_attempt(MutationAttemptId attempt) noexcept {
  impl_->pinned_attempt = attempt;
}

CoordinatorEpoch EcmpClient::epoch() const noexcept { return impl_->epoch; }

PublisherId EcmpClient::publisher() const noexcept { return impl_->publisher; }

WorkerBootId EcmpClient::worker_boot() const noexcept { return impl_->worker_boot; }

bool EcmpClient::round_trip(WireMessageId request_id, const std::vector<std::uint8_t>& payload,
                            WireMessageId expected, Envelope& response, std::string& error) {
  Envelope envelope;
  envelope.message = request_id;
  envelope.epoch = impl_->epoch;
  envelope.publisher = impl_->publisher;
  envelope.worker_boot = impl_->worker_boot;
  envelope.attempt = impl_->next_attempt();
  envelope.payload = payload;
  if (!write_frame(impl_->connection, envelope, impl_->limits, error)) {
    return false;
  }
  Envelope incoming;
  const WireDefect defect =
      read_frame(impl_->connection, impl_->limits, impl_->deadline_ms, incoming, error);
  if (defect != WireDefect::NONE) {
    error = std::string(to_string(defect));
    return false;
  }
  if (incoming.message == WireMessageId::ERROR) {
    ErrorBody body;
    if (decode_error_body(incoming.payload, impl_->limits, body)) {
      error = std::string(to_string(body.code)) + ":" + body.detail;
    } else {
      error = "error response";
    }
    return false;
  }
  if (incoming.message != expected) {
    error = "unexpected response " + std::string(to_string(incoming.message));
    return false;
  }
  response = std::move(incoming);
  return true;
}

bool EcmpClient::hello(HelloResponseBody& out, std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::HELLO, {}, WireMessageId::HELLO_RESPONSE, response,
                  error)) {
    return false;
  }
  if (!decode_hello_response(response.payload, impl_->limits, out)) {
    error = "malformed hello response";
    return false;
  }
  impl_->epoch = out.epoch;
  return true;
}

bool EcmpClient::register_publisher(const PublisherRegistration& registration,
                                    RegisterPublisherResponseBody& out, std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::REGISTER_PUBLISHER, encode_payload(registration),
                  WireMessageId::REGISTER_PUBLISHER_RESPONSE, response, error)) {
    return false;
  }
  if (!decode_register_publisher_response(response.payload, impl_->limits, out)) {
    error = "malformed registration response";
    return false;
  }
  return true;
}

bool EcmpClient::create_group(const CreateGroupRequest& request, MutationResult& out,
                              std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::CREATE_GROUP, encode_payload(request),
                  WireMessageId::CREATE_GROUP_RESPONSE, response, error)) {
    return false;
  }
  return decode_mutation_result(response.payload, impl_->limits, out);
}

bool EcmpClient::add_member(const AddMemberRequest& request, MutationResult& out,
                            std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::ADD_MEMBER, encode_payload(request),
                  WireMessageId::ADD_MEMBER_RESPONSE, response, error)) {
    return false;
  }
  return decode_mutation_result(response.payload, impl_->limits, out);
}

bool EcmpClient::remove_member(const RemoveMemberRequest& request, MutationResult& out,
                               std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::REMOVE_MEMBER, encode_payload(request),
                  WireMessageId::REMOVE_MEMBER_RESPONSE, response, error)) {
    return false;
  }
  return decode_mutation_result(response.payload, impl_->limits, out);
}

bool EcmpClient::set_member_enabled(const SetMemberEnabledRequest& request, MutationResult& out,
                                    std::string& error) {
  const WireMessageId id = request.enabled ? WireMessageId::ENABLE_MEMBER
                                           : WireMessageId::DISABLE_MEMBER;
  const WireMessageId expected = request.enabled ? WireMessageId::ENABLE_MEMBER_RESPONSE
                                                 : WireMessageId::DISABLE_MEMBER_RESPONSE;
  Envelope response;
  if (!round_trip(id, encode_payload(request), expected, response, error)) {
    return false;
  }
  return decode_mutation_result(response.payload, impl_->limits, out);
}

bool EcmpClient::revalidate_group(const RevalidateGroupRequest& request, MutationResult& out,
                                  std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::REVALIDATE_GROUP, encode_payload(request),
                  WireMessageId::REVALIDATE_GROUP_RESPONSE, response, error)) {
    return false;
  }
  return decode_mutation_result(response.payload, impl_->limits, out);
}

bool EcmpClient::plan_rebalance(const RebalancePlanRequest& request, MutationResult& out,
                                std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::PLAN_REBALANCE, encode_payload(request),
                  WireMessageId::PLAN_REBALANCE_RESPONSE, response, error)) {
    return false;
  }
  return decode_mutation_result(response.payload, impl_->limits, out);
}

bool EcmpClient::commit_rebalance(const RebalanceCommitRequest& request, MutationResult& out,
                                  std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::COMMIT_REBALANCE, encode_payload(request),
                  WireMessageId::REBALANCE_RESULT, response, error)) {
    return false;
  }
  RebalanceResultBody body;
  if (!decode_rebalance_result(response.payload, impl_->limits, body)) {
    error = "malformed rebalance result";
    return false;
  }
  out = std::move(body.result);
  return true;
}

bool EcmpClient::snapshot(const ECMPGroupId& group, SnapshotResponseBody& out,
                          std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::SNAPSHOT_REQUEST, encode_payload(group),
                  WireMessageId::SNAPSHOT_RESPONSE, response, error)) {
    return false;
  }
  return decode_snapshot_response(response.payload, impl_->limits, out);
}

bool EcmpClient::list_groups(ListGroupsResponseBody& out, std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::LIST_GROUPS, {}, WireMessageId::LIST_GROUPS_RESPONSE,
                  response, error)) {
    return false;
  }
  return decode_list_groups_response(response.payload, impl_->limits, out);
}

bool EcmpClient::explain(const ExplainRequest& request, ExplainResponseBody& out,
                         std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::EXPLAIN_REQUEST, encode_payload(request),
                  WireMessageId::EXPLAIN_RESPONSE, response, error)) {
    return false;
  }
  return decode_explain_response(response.payload, impl_->limits, out);
}

bool EcmpClient::notify_path_authority_change(const PathAuthorityChangeNotice& notice,
                                              MutationResult& out, std::string& error) {
  Envelope response;
  if (!round_trip(WireMessageId::PATH_AUTHORITY_CHANGE, encode_payload(notice),
                  WireMessageId::PATH_AUTHORITY_CHANGE_RESPONSE, response, error)) {
    return false;
  }
  return decode_mutation_result(response.payload, impl_->limits, out);
}

bool EcmpClient::wait_for_fence(std::string& error) {
  for (;;) {
    Envelope incoming;
    const WireDefect defect = read_frame(impl_->connection, impl_->limits, 0, incoming, error);
    if (defect != WireDefect::NONE) {
      return false;
    }
    if (incoming.message == WireMessageId::FENCE_NOTICE) {
      return true;
    }
  }
}

void EcmpClient::close() {
  if (impl_) {
    impl_->connected = false;
    impl_->connection.close();
  }
}

}  // namespace ecmp
