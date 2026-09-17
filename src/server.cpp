#include "ecmp/server.hpp"

#include <array>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "ecmp/bytes.hpp"
#include "ecmp/protocol.hpp"
#include "ecmp/version.hpp"

namespace ecmp {
namespace {

WireMessageId response_for(WireMessageId request) noexcept {
  switch (request) {
    case WireMessageId::HELLO: return WireMessageId::HELLO_RESPONSE;
    case WireMessageId::REGISTER_PUBLISHER: return WireMessageId::REGISTER_PUBLISHER_RESPONSE;
    case WireMessageId::CREATE_GROUP: return WireMessageId::CREATE_GROUP_RESPONSE;
    case WireMessageId::ADD_MEMBER: return WireMessageId::ADD_MEMBER_RESPONSE;
    case WireMessageId::REMOVE_MEMBER: return WireMessageId::REMOVE_MEMBER_RESPONSE;
    case WireMessageId::DISABLE_MEMBER: return WireMessageId::DISABLE_MEMBER_RESPONSE;
    case WireMessageId::ENABLE_MEMBER: return WireMessageId::ENABLE_MEMBER_RESPONSE;
    case WireMessageId::REVALIDATE_GROUP: return WireMessageId::REVALIDATE_GROUP_RESPONSE;
    case WireMessageId::PLAN_REBALANCE: return WireMessageId::PLAN_REBALANCE_RESPONSE;
    case WireMessageId::COMMIT_REBALANCE: return WireMessageId::REBALANCE_RESULT;
    case WireMessageId::QUERY_GROUP: return WireMessageId::QUERY_GROUP_RESPONSE;
    case WireMessageId::SNAPSHOT_REQUEST: return WireMessageId::SNAPSHOT_RESPONSE;
    case WireMessageId::LIST_GROUPS: return WireMessageId::LIST_GROUPS_RESPONSE;
    case WireMessageId::PATH_AUTHORITY_CHANGE:
      return WireMessageId::PATH_AUTHORITY_CHANGE_RESPONSE;
    case WireMessageId::EXPLAIN_REQUEST: return WireMessageId::EXPLAIN_RESPONSE;
    default: return WireMessageId::ERROR;
  }
}

}  // namespace

struct CoordinatorServer::Impl {
  struct Session {
    std::shared_ptr<TcpConnection> connection;
    PublisherId publisher;
    WorkerBootId worker_boot;
    bool registered = false;
  };

  EcmpGovernor* governor = nullptr;
  CoordinatorServerOptions options;
  TcpListener listener;
  std::atomic<bool> stopping{false};
  std::atomic<std::uint64_t> handled{0};
  std::atomic<std::uint32_t> sessions{0};
  std::mutex session_mutex;
  std::map<PublisherId, std::shared_ptr<Session>> by_publisher;
  std::vector<std::shared_ptr<Session>> live_sessions;
  std::mutex thread_mutex;
  std::vector<std::thread> threads;
  // One mutation and its autosave at a time: the durable store always reflects a
  // monotonically newer state and the coordinator remains a single writer.
  std::mutex mutate_mutex;

  [[nodiscard]] AuthorityContext authority_of(const Envelope& envelope) const {
    AuthorityContext context;
    context.epoch = envelope.epoch;
    context.publisher = envelope.publisher;
    context.worker_boot = envelope.worker_boot;
    context.attempt = envelope.attempt_or_default();
    const std::optional<PublisherRegistration> registration =
        governor->registration(envelope.publisher);
    if (registration.has_value() && registration->worker_boot == envelope.worker_boot) {
      context.scope = registration->scope;
    }
    return context;
  }

  void autosave() {
    if (!options.autosave || options.store_path.empty()) {
      return;
    }
    (void)governor->save(options.store_path);
  }

  static void fail(Envelope& response, ConditionCode code, Outcome outcome,
                   const std::string& detail) {
    response.message = WireMessageId::ERROR;
    ErrorBody body;
    body.code = code;
    body.outcome = outcome;
    body.detail = detail;
    response.payload = encode_error_body(body);
  }

  void register_session(const std::shared_ptr<Session>& session,
                        const PublisherRegistration& registration) {
    std::shared_ptr<Session> previous;
    {
      std::lock_guard<std::mutex> lock(session_mutex);
      const auto it = by_publisher.find(registration.publisher);
      if (it != by_publisher.end() && !(it->second->worker_boot == registration.worker_boot)) {
        previous = it->second;
        by_publisher.erase(it);
      }
      by_publisher[registration.publisher] = session;
    }
    session->publisher = registration.publisher;
    session->worker_boot = registration.worker_boot;
    session->registered = true;
    if (!previous) {
      return;
    }
    // The superseded incarnation is told explicitly that it has been fenced, and
    // its connection is shut down so a blocked read returns immediately.
    Envelope notice;
    notice.message = WireMessageId::FENCE_NOTICE;
    notice.epoch = governor->epoch();
    notice.publisher = registration.publisher;
    notice.worker_boot = previous->worker_boot;
    ErrorBody body;
    body.code = ConditionCode::WORKER_FENCED;
    body.outcome = Outcome::FENCED;
    body.detail = "session superseded by a fresh worker boot";
    notice.payload = encode_error_body(body);
    std::string error;
    (void)write_frame(*previous->connection, notice, options.limits, error);
    previous->connection->shutdown();
  }

  void end_session(const std::shared_ptr<Session>& session) {
    if (session->registered) {
      ConditionList conditions(options.limits.max_explanation_entries);
      (void)governor->fence_publisher(session->publisher, session->worker_boot, conditions);
      std::lock_guard<std::mutex> lock(session_mutex);
      const auto it = by_publisher.find(session->publisher);
      if (it != by_publisher.end() && it->second.get() == session.get()) {
        by_publisher.erase(it);
      }
    }
    session->connection->close();
    --sessions;
  }

  void handle_request(const Envelope& request, const std::shared_ptr<Session>& session,
                      Envelope& response) {
    response.message = response_for(request.message);
    response.epoch = governor->epoch();
    switch (request.message) {
      case WireMessageId::HELLO: {
        HelloResponseBody body;
        body.wire_version = kWireVersion;
        body.epoch = governor->epoch();
        body.product = std::string(kProductName);
        body.version = std::string(kVersionString);
        response.payload = encode_hello_response(body);
        return;
      }
      case WireMessageId::REGISTER_PUBLISHER: {
        PublisherRegistration registration;
        if (!decode_payload(request.payload, options.limits, registration)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "register_publisher");
          return;
        }
        ConditionList conditions(options.limits.max_explanation_entries);
        const Outcome outcome =
            governor->register_publisher(request.epoch, registration, conditions);
        RegisterPublisherResponseBody body;
        body.outcome = outcome;
        body.conditions = conditions;
        response.payload = encode_register_publisher_response(body);
        if (is_acceptance(outcome)) {
          register_session(session, registration);
        }
        return;
      }
      case WireMessageId::CREATE_GROUP: {
        CreateGroupRequest typed;
        if (!decode_payload(request.payload, options.limits, typed)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "create_group");
          return;
        }
        typed.authority = authority_of(request);
        std::lock_guard<std::mutex> lock(mutate_mutex);
        const MutationResult result = governor->create_group(typed);
        if (is_acceptance(result.outcome)) {
          autosave();
        }
        response.payload = encode_mutation_result(result);
        return;
      }
      case WireMessageId::ADD_MEMBER: {
        AddMemberRequest typed;
        if (!decode_payload(request.payload, options.limits, typed)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "add_member");
          return;
        }
        typed.authority = authority_of(request);
        std::lock_guard<std::mutex> lock(mutate_mutex);
        const MutationResult result = governor->add_member(typed);
        if (is_acceptance(result.outcome)) {
          autosave();
        }
        response.payload = encode_mutation_result(result);
        return;
      }
      case WireMessageId::REMOVE_MEMBER: {
        RemoveMemberRequest typed;
        if (!decode_payload(request.payload, options.limits, typed)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "remove_member");
          return;
        }
        typed.authority = authority_of(request);
        std::lock_guard<std::mutex> lock(mutate_mutex);
        const MutationResult result = governor->remove_member(typed);
        if (is_acceptance(result.outcome)) {
          autosave();
        }
        response.payload = encode_mutation_result(result);
        return;
      }
      case WireMessageId::DISABLE_MEMBER:
      case WireMessageId::ENABLE_MEMBER: {
        SetMemberEnabledRequest typed;
        if (!decode_payload(request.payload, options.limits, typed)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "set_member_enabled");
          return;
        }
        typed.enabled = request.message == WireMessageId::ENABLE_MEMBER;
        typed.authority = authority_of(request);
        std::lock_guard<std::mutex> lock(mutate_mutex);
        const MutationResult result = governor->set_member_enabled(typed);
        if (is_acceptance(result.outcome)) {
          autosave();
        }
        response.payload = encode_mutation_result(result);
        return;
      }
      case WireMessageId::REVALIDATE_GROUP: {
        RevalidateGroupRequest typed;
        if (!decode_payload(request.payload, options.limits, typed)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "revalidate_group");
          return;
        }
        typed.authority = authority_of(request);
        std::lock_guard<std::mutex> lock(mutate_mutex);
        const MutationResult result = governor->revalidate_group(typed);
        if (is_acceptance(result.outcome)) {
          autosave();
        }
        response.payload = encode_mutation_result(result);
        return;
      }
      case WireMessageId::PLAN_REBALANCE: {
        RebalancePlanRequest typed;
        if (!decode_payload(request.payload, options.limits, typed)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "plan_rebalance");
          return;
        }
        typed.authority = authority_of(request);
        std::lock_guard<std::mutex> lock(mutate_mutex);
        const MutationResult result = governor->plan_rebalance(typed);
        if (is_acceptance(result.outcome)) {
          autosave();
        }
        response.payload = encode_mutation_result(result);
        return;
      }
      case WireMessageId::COMMIT_REBALANCE: {
        RebalanceCommitRequest typed;
        if (!decode_payload(request.payload, options.limits, typed)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "commit_rebalance");
          return;
        }
        typed.authority = authority_of(request);
        std::lock_guard<std::mutex> lock(mutate_mutex);
        const MutationResult result = governor->commit_rebalance(typed);
        if (is_acceptance(result.outcome)) {
          autosave();
        }
        RebalanceResultBody body;
        body.result = result;
        const std::optional<RebalanceRecord> record = governor->last_rebalance(typed.group);
        if (record.has_value()) {
          body.record = *record;
        }
        response.payload = encode_rebalance_result(body);
        return;
      }
      case WireMessageId::QUERY_GROUP: {
        ECMPGroupId group;
        if (!decode_payload(request.payload, options.limits, group)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "query_group");
          return;
        }
        GroupQueryResponseBody body;
        const std::optional<GroupSnapshot> snapshot = governor->snapshot(group);
        if (snapshot.has_value()) {
          body.found = true;
          body.summary = summarize(*snapshot);
        }
        response.payload = encode_group_query_response(body);
        return;
      }
      case WireMessageId::SNAPSHOT_REQUEST: {
        ECMPGroupId group;
        if (!decode_payload(request.payload, options.limits, group)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "snapshot_request");
          return;
        }
        SnapshotResponseBody body;
        const std::optional<GroupSnapshot> snapshot = governor->snapshot(group);
        if (snapshot.has_value()) {
          body.found = true;
          body.snapshot = *snapshot;
        }
        response.payload = encode_snapshot_response(body);
        return;
      }
      case WireMessageId::PATH_AUTHORITY_CHANGE: {
        PathAuthorityChangeNotice notice;
        if (!decode_payload(request.payload, options.limits, notice)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST,
               "path_authority_change");
          return;
        }
        notice.epoch = request.epoch;
        notice.publisher = request.publisher;
        notice.worker_boot = request.worker_boot;
        if (options.upstream_hook != nullptr) {
          options.upstream_hook->on_path_authority_change(notice);
        }
        std::lock_guard<std::mutex> lock(mutate_mutex);
        const MutationResult result = governor->notify_path_authority_change(notice);
        if (is_acceptance(result.outcome)) {
          autosave();
        }
        response.payload = encode_mutation_result(result);
        return;
      }
      case WireMessageId::EXPLAIN_REQUEST: {
        ExplainRequest typed;
        if (!decode_payload(request.payload, options.limits, typed)) {
          fail(response, ConditionCode::MALFORMED_PAYLOAD, Outcome::MALFORMED_REQUEST, "explain");
          return;
        }
        ExplainResponseBody body;
        Explanation explanation;
        switch (typed.kind) {
          case ExplainKind::GROUP:
            explanation = governor->explain_group(typed.group);
            break;
          case ExplainKind::MEMBER:
            explanation = governor->explain_member(typed.group, typed.member);
            break;
          case ExplainKind::BUCKET:
            explanation = governor->explain_bucket(typed.group, typed.bucket);
            break;
          case ExplainKind::LAST_REBALANCE:
            explanation = governor->explain_last_rebalance(typed.group);
            break;
          case ExplainKind::AUTHORITY:
            explanation = governor->explain_authority(typed.group);
            break;
        }
        body.found = !(explanation.conditions().entries().size() == 1 &&
                       explanation.conditions().entries().front().code ==
                           ConditionCode::GROUP_UNKNOWN);
        body.text = explanation.render();
        response.payload = encode_explain_response(body);
        return;
      }
      case WireMessageId::LIST_GROUPS: {
        ListGroupsResponseBody body;
        body.groups = governor->list_groups();
        response.payload = encode_list_groups_response(body);
        return;
      }
      default:
        fail(response, ConditionCode::WIRE_UNKNOWN_MESSAGE, Outcome::WIRE_REJECTED,
             std::string(to_string(request.message)));
        return;
    }
  }

  void handle_session(TcpConnection connection) {
    const auto session = std::make_shared<Session>();
    session->connection = std::make_shared<TcpConnection>(std::move(connection));
    for (;;) {
      if (stopping) {
        break;
      }
      Envelope request;
      std::string error;
      const WireDefect defect = read_frame(*session->connection, options.limits,
                                           options.receive_deadline_ms, request, error);
      if (defect == WireDefect::PEER_CLOSED) {
        break;
      }
      if (defect != WireDefect::NONE) {
        Envelope response;
        response.epoch = governor->epoch();
        fail(response, condition_for(defect), Outcome::WIRE_REJECTED,
             std::string(to_string(defect)));
        std::string write_error;
        (void)write_frame(*session->connection, response, options.limits, write_error);
        break;
      }
      ++handled;
      if (options.max_requests != 0 && handled > options.max_requests) {
        break;
      }
      Envelope response;
      handle_request(request, session, response);
      std::string write_error;
      if (!write_frame(*session->connection, response, options.limits, write_error)) {
        break;
      }
      if (options.max_requests != 0 && handled >= options.max_requests) {
        stopping = true;
        listener.close();
        break;
      }
    }
    end_session(session);
  }
};

CoordinatorServer::CoordinatorServer(EcmpGovernor& governor, CoordinatorServerOptions options)
    : impl_(std::make_unique<Impl>()) {
  impl_->governor = &governor;
  impl_->options = std::move(options);
}

CoordinatorServer::~CoordinatorServer() { stop(); }

bool CoordinatorServer::start(std::string& error) {
  std::optional<TcpListener> listener =
      TcpListener::bind_loopback(impl_->options.port, error);
  if (!listener.has_value()) {
    return false;
  }
  impl_->listener = std::move(*listener);
  return true;
}

std::uint16_t CoordinatorServer::port() const { return impl_->listener.port(); }

std::uint32_t CoordinatorServer::active_sessions() const { return impl_->sessions; }

std::uint64_t CoordinatorServer::handled_requests() const { return impl_->handled; }

void CoordinatorServer::serve() {
  while (!impl_->stopping) {
    std::string error;
    std::optional<TcpConnection> connection = impl_->listener.accept(error);
    if (!connection.has_value()) {
      if (impl_->stopping) {
        break;
      }
      break;
    }
    if (impl_->sessions >= impl_->options.limits.max_sessions) {
      Envelope response;
      response.epoch = impl_->governor->epoch();
      Impl::fail(response, ConditionCode::SESSION_LIMIT, Outcome::RESOURCE_LIMIT,
                 "session limit reached");
      std::string write_error;
      (void)write_frame(*connection, response, impl_->options.limits, write_error);
      connection->close();
      continue;
    }
    ++impl_->sessions;
    std::thread thread([this, moved = std::move(*connection)]() mutable {
      impl_->handle_session(std::move(moved));
    });
    std::lock_guard<std::mutex> lock(impl_->thread_mutex);
    impl_->threads.push_back(std::move(thread));
  }
}

void CoordinatorServer::stop() {
  if (!impl_) {
    return;
  }
  impl_->stopping = true;
  impl_->listener.close();
  {
    std::lock_guard<std::mutex> lock(impl_->session_mutex);
    for (const auto& entry : impl_->by_publisher) {
      entry.second->connection->shutdown();
    }
  }
  {
    std::lock_guard<std::mutex> lock(impl_->thread_mutex);
    for (std::thread& thread : impl_->threads) {
      if (thread.joinable()) {
        thread.join();
      }
    }
    impl_->threads.clear();
  }
}

}  // namespace ecmp
