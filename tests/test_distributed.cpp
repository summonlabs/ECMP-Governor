#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ecmp/client.hpp"
#include "ecmp/ecmp.hpp"
#include "ecmp/process.hpp"
#include "test_framework.hpp"

namespace {

using namespace ecmp;

#ifndef ECMP_COORDINATOR_EXECUTABLE
#define ECMP_COORDINATOR_EXECUTABLE "ecmp_coordinator"
#endif
#ifndef ECMP_WORKER_EXECUTABLE
#define ECMP_WORKER_EXECUTABLE "ecmp_worker"
#endif

std::filesystem::path scratch_directory(const std::string& name) {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / ("ecmp-governor-" + name);
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  std::filesystem::create_directories(directory, error);
  return directory;
}

std::string token(const std::string& line, const std::string& key) {
  const std::size_t position = line.find(key);
  if (position == std::string::npos) {
    return {};
  }
  const std::size_t start = position + key.size();
  const std::size_t end = line.find(' ', start);
  return line.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

struct Coordinator {
  LocalProcess process;
  std::uint16_t port = 0;
  CoordinatorEpoch epoch;
  std::uint32_t recovered = 0;
  std::filesystem::path store;
  std::filesystem::path view;
};

bool start_coordinator(Coordinator& coordinator, const std::filesystem::path& store,
                       const std::filesystem::path& view, std::string& error) {
  LocalProcess::Options options;
  options.executable = ECMP_COORDINATOR_EXECUTABLE;
  options.arguments = {"--store", store.string(), "--port", "0", "--authority-view",
                       view.string()};
  std::optional<LocalProcess> process = LocalProcess::spawn(options, error);
  if (!process.has_value()) {
    return false;
  }
  coordinator.process = std::move(*process);
  coordinator.store = store;
  coordinator.view = view;
  std::string line;
  while (coordinator.process.read_line(line)) {
    if (line.rfind("ECMP_COORDINATOR_READY", 0) == 0) {
      coordinator.port = static_cast<std::uint16_t>(std::stoul(token(line, "port=")));
      coordinator.epoch = CoordinatorEpoch::from_value(std::stoull(token(line, "epoch=")));
      coordinator.recovered =
          static_cast<std::uint32_t>(std::stoul(token(line, "recovered_groups=")));
      return true;
    }
    if (line.rfind("ECMP_COORDINATOR_ERROR", 0) == 0) {
      error = line;
      return false;
    }
  }
  error = "coordinator exited before becoming ready";
  return false;
}

std::vector<std::string> worker_arguments(std::uint16_t port, const std::string& scenario,
                                          const PublisherId& publisher, const WorkerBootId& boot) {
  return {"--port", std::to_string(port), "--scenario", scenario, "--publisher",
          publisher.to_text(), "--boot", boot.to_text(), "--group-seed", "1", "--paths", "4",
          "--buckets", "64", "--min-active", "2", "--path-seed-base", "1000",
          "--member-seed-base", "2000"};
}

// Runs a worker scenario to completion and returns its output lines.
std::vector<std::string> run_worker(std::uint16_t port, const std::string& scenario,
                                    const PublisherId& publisher, const WorkerBootId& boot,
                                    const std::vector<std::string>& extra = {}) {
  LocalProcess::Options options;
  options.executable = ECMP_WORKER_EXECUTABLE;
  options.arguments = worker_arguments(port, scenario, publisher, boot);
  options.arguments.insert(options.arguments.end(), extra.begin(), extra.end());
  std::string error;
  std::vector<std::string> lines;
  std::optional<LocalProcess> process = LocalProcess::spawn(options, error);
  if (!process.has_value()) {
    ::ecmp::test::report_failure(__FILE__, __LINE__, "worker spawn failed: " + error);
    return lines;
  }
  std::string line;
  while (process->read_line(line)) {
    lines.push_back(line);
  }
  (void)process->wait_for_exit();
  return lines;
}

std::string join(const std::vector<std::string>& lines) {
  std::string out;
  for (const std::string& line : lines) {
    out += line;
    out += " | ";
  }
  return out;
}

bool has_line(const std::vector<std::string>& lines, const std::string& needle) {
  for (const std::string& line : lines) {
    if (line.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

std::string line_with(const std::vector<std::string>& lines, const std::string& needle) {
  for (const std::string& line : lines) {
    if (line.find(needle) != std::string::npos) {
      return line;
    }
  }
  return {};
}

void write_authority_view(const std::filesystem::path& path, std::uint32_t paths,
                          std::uint64_t generation, bool authorized = true) {
  std::ofstream out(path, std::ios::trunc);
  for (std::uint32_t index = 0; index < paths; ++index) {
    out << "authority " << synthetic_path_id(1000 + index).to_text() << ' ' << generation << ' '
        << (authorized ? 1 : 0) << '\n';
  }
}

struct Session {
  EcmpClient client;
  CoordinatorEpoch epoch;
  PublisherId publisher = synthetic_publisher_id(7001);
  WorkerBootId boot = synthetic_boot_id(7001);
  SyntheticIds ids = synthetic_ids(1);
  ECMPGroupId group = synthetic_group_id(1);

  bool open(std::uint16_t port, std::string& error) {
    std::optional<EcmpClient> connected = EcmpClient::connect("127.0.0.1", port, 5000, error);
    if (!connected.has_value()) {
      return false;
    }
    client = std::move(*connected);
    HelloResponseBody hello;
    if (!client.hello(hello, error)) {
      return false;
    }
    epoch = hello.epoch;
    client.set_publisher(publisher);
    client.set_worker_boot(boot);
    return true;
  }

  bool register_publisher(std::uint16_t port, WorkerBootId boot_id, std::uint32_t capabilities,
                          std::string& error) {
    (void)port;
    PublisherRegistration registration;
    registration.publisher = publisher;
    registration.worker_boot = boot_id;
    registration.scope = AuthorityScope::for_fabric(ids.fabric);
    registration.capabilities = capabilities;
    registration.provenance = ids.provenance;
    client.set_worker_boot(boot_id);
    RegisterPublisherResponseBody body;
    if (!client.register_publisher(registration, body, error)) {
      return false;
    }
    return is_acceptance(body.outcome) ||
           body.outcome == Outcome::STALE_WORKER ||
           body.outcome == Outcome::STALE_EPOCH ||
           body.outcome == Outcome::RESOURCE_LIMIT;
  }

  RegisterPublisherResponseBody try_register(std::uint16_t port, PublisherId publisher_id,
                                             WorkerBootId boot_id, std::string& error) {
    (void)port;
    PublisherRegistration registration;
    registration.publisher = publisher_id;
    registration.worker_boot = boot_id;
    registration.scope = AuthorityScope::for_fabric(ids.fabric);
    registration.capabilities = 3;
    registration.provenance = ids.provenance;
    RegisterPublisherResponseBody body;
    RegisterPublisherResponseBody result;
    client.set_publisher(publisher_id);
    client.set_worker_boot(boot_id);
    if (!client.register_publisher(registration, result, error)) {
      return body;
    }
    return result;
  }

  std::optional<GroupSnapshot> snapshot(std::string& error) {
    SnapshotResponseBody body;
    if (!client.snapshot(group, body, error)) {
      return std::nullopt;
    }
    if (!body.found) {
      return std::nullopt;
    }
    return body.snapshot;
  }

  bool authority_gap(const ECMPGroupId& target) {
    ExplainRequest request;
    request.group = target;
    request.kind = ExplainKind::AUTHORITY;
    ExplainResponseBody body;
    std::string error;
    if (!client.explain(request, body, error)) {
      return false;
    }
    return body.text.find("subject=authority_current observed=0") != std::string::npos;
  }
};

// Bounded internal wait.  Exhausting the bound produces an explicit failed
// assertion, never a silent pass, and there is no watchdog suppressing a hang.
bool wait_for_authority_gap(Session& session, const ECMPGroupId& group,
                            const std::string& description) {
  for (int attempt = 0; attempt < 4000; ++attempt) {
    if (session.authority_gap(group)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  ::ecmp::test::report_failure(__FILE__, __LINE__,
                               "bounded wait exhausted without the expected state: " +
                                   description);
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// REAL worker-death proof: a real OS process is terminated and its authority is
// fenced by the coordinator; a fresh boot for the same publisher identity may
// re-register and revalidate, and the dead boot can never mutate again.
// ---------------------------------------------------------------------------

ECMP_TEST(test_real_worker_death_fences_authority_and_preserves_durable_state) {
  const std::filesystem::path directory = scratch_directory("worker-death");
  const std::filesystem::path store = directory / "governor.store";
  const std::filesystem::path view = directory / "authority.view";
  write_authority_view(view, 8, 1);

  Coordinator coordinator;
  std::string error;
  ECMP_REQUIRE(start_coordinator(coordinator, store, view, error));
  ECMP_CHECK_EQ(coordinator.epoch.value(), std::uint64_t{1});

  const PublisherId publisher_a = synthetic_publisher_id(1);
  const WorkerBootId boot_a1 = synthetic_boot_id(1);
  const PublisherId publisher_b = synthetic_publisher_id(2);
  const WorkerBootId boot_b = synthetic_boot_id(2);

  // An unrelated publisher owns a second group; it must be untouched throughout.
  Session observer;
  ECMP_REQUIRE(observer.open(coordinator.port, error));
  Session unrelated;
  ECMP_REQUIRE(unrelated.open(coordinator.port, error));
  unrelated.publisher = publisher_b;
  unrelated.boot = boot_b;
  unrelated.ids = synthetic_ids(2);
  unrelated.group = synthetic_group_id(2);
  unrelated.client.set_publisher(publisher_b);
  unrelated.client.set_worker_boot(boot_b);
  ECMP_REQUIRE(unrelated.register_publisher(coordinator.port, boot_b, 3, error));
  {
    CreateGroupRequest request;
    request.authority.epoch = unrelated.epoch;
    request.authority.publisher = publisher_b;
    request.authority.worker_boot = boot_b;
    request.authority.scope = AuthorityScope::for_fabric(unrelated.ids.fabric);
    request.authority.attempt = synthetic_attempt_id(5001);
    request.group = unrelated.group;
    request.key = synthetic_group_key(unrelated.ids);
    request.cost_semantics = synthetic_cost_semantics(unrelated.ids, 1);
    request.hash_domain = unrelated.ids.hash_domain;
    request.provenance = unrelated.ids.provenance;
    request.bucket_count = *BucketCount::make(32);
    request.min_active_members = 1;
    request.members = synthetic_members(unrelated.ids, 2, PathAuthorityGeneration::from_value(1));
    MutationResult result;
    ECMP_REQUIRE(unrelated.client.create_group(request, result, error));
    ECMP_REQUIRE(is_acceptance(result.outcome));
  }
  std::string snapshot_error;
  const std::optional<GroupSnapshot> unrelated_before = unrelated.snapshot(snapshot_error);
  ECMP_REQUIRE(unrelated_before.has_value());
  const Digest unrelated_digest = unrelated_before->semantic_digest;

  // Publisher A creates the governed group and then holds its connection open.
  LocalProcess::Options options;
  options.executable = ECMP_WORKER_EXECUTABLE;
  options.arguments = worker_arguments(coordinator.port, "hold", publisher_a, boot_a1);
  std::optional<LocalProcess> worker = LocalProcess::spawn(options, error);
  ECMP_REQUIRE(worker.has_value());
  bool holding = false;
  std::string line;
  while (worker->read_line(line)) {
    if (line.find("ECMP_WORKER_RESULT") != std::string::npos) {
      ECMP_CHECK(line.find("outcome=CREATED") != std::string::npos);
    }
    if (line.find("ECMP_WORKER_HOLDING") != std::string::npos) {
      holding = true;
      break;
    }
  }
  ECMP_REQUIRE(holding);
  ECMP_CHECK(worker->running());
  ECMP_CHECK(worker->pid() != 0);

  Session observer_group;
  ECMP_REQUIRE(observer_group.open(coordinator.port, error));
  const std::optional<GroupSnapshot> active = observer_group.snapshot(snapshot_error);
  ECMP_REQUIRE(active.has_value());
  ECMP_CHECK(active->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK_EQ(active->active_member_count(), std::uint32_t{4});
  const Digest assignment_digest = active->assignment_digest;
  ECMP_CHECK(active->currentness.authority_current());

  // Kill the worker with a real OS process termination.
  ECMP_REQUIRE(worker->running());
  ECMP_CHECK(worker->terminate());
  ECMP_CHECK(!worker->running());

  // The coordinator detects the disconnect and fences the incarnation.
  ECMP_CHECK(wait_for_authority_gap(observer_group, observer_group.group,
                                    "coordinator fences the dead worker"));

  // The durable group description survives with its assignment intact.
  const std::optional<GroupSnapshot> after_death = observer_group.snapshot(snapshot_error);
  ECMP_REQUIRE(after_death.has_value());
  ECMP_CHECK(after_death->lifecycle == GroupLifecycle::REVALIDATION_REQUIRED);
  ECMP_CHECK(after_death->currentness.has(CurrentnessCause::FENCED_PUBLISHER));
  ECMP_CHECK(after_death->assignment_digest == assignment_digest);

  // The dead boot may never mutate again, and may not even re-register.
  {
    RegisterPublisherResponseBody body =
        observer.try_register(coordinator.port, publisher_a, boot_a1, error);
    if (body.outcome != Outcome::STALE_WORKER) {
      ::ecmp::test::report_failure(__FILE__, __LINE__,
                                   std::string("dead boot registration: expected STALE_WORKER, got ") +
                                       std::string(to_string(body.outcome)) + " error=" + error);
    }
  }

  // A fresh boot for the same publisher identity is a fresh registration.
  {
    RegisterPublisherResponseBody body =
        observer.try_register(coordinator.port, publisher_a, synthetic_boot_id(11), error);
    if (body.outcome != Outcome::REGISTERED) {
      ::ecmp::test::report_failure(__FILE__, __LINE__,
                                   std::string("fresh boot registration: expected REGISTERED, got ") +
                                       std::string(to_string(body.outcome)) + " error=" + error);
    }
  }

  // The fresh incarnation revalidates the group: the identical assignment returns.
  {
    RevalidateGroupRequest request;
    request.authority.epoch = observer.epoch;
    request.authority.publisher = publisher_a;
    request.authority.worker_boot = synthetic_boot_id(11);
    request.authority.scope = AuthorityScope::for_fabric(observer.ids.fabric);
    request.authority.attempt = synthetic_attempt_id(6001);
    request.group = observer_group.group;
    for (std::uint32_t index = 0; index < 4; ++index) {
      MemberRevalidation update;
      update.member = synthetic_member_id(2000 + index);
      update.path_authority = PathAuthorityGeneration::from_value(1);
      request.members.push_back(update);
    }
    MutationResult result;
    if (!observer.client.revalidate_group(request, result, error)) {
      ::ecmp::test::report_failure(__FILE__, __LINE__, "revalidate request failed: " + error);
    }
    if (!is_acceptance(result.outcome)) {
      ::ecmp::test::report_failure(__FILE__, __LINE__,
                                   std::string("revalidate rejected: ") +
                                       std::string(to_string(result.outcome)));
    }
  }
  const std::optional<GroupSnapshot> restored = observer_group.snapshot(snapshot_error);
  ECMP_REQUIRE(restored.has_value());
  ECMP_CHECK(restored->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK(restored->currentness.is_current());
  ECMP_CHECK(restored->assignment_digest == assignment_digest);

  // The dead boot still cannot mutate after the group has been restored.  The
  // authority identity travels in the frame envelope, so the stale incarnation is
  // presented exactly the way a stale worker process would present it.
  {
    observer.client.set_worker_boot(boot_a1);
    AddMemberRequest request;
    request.authority.epoch = observer.epoch;
    request.authority.publisher = publisher_a;
    request.authority.worker_boot = boot_a1;
    request.authority.scope = AuthorityScope::for_fabric(observer.ids.fabric);
    request.authority.attempt = synthetic_attempt_id(6002);
    request.group = observer_group.group;
    request.member = synthetic_member_spec(observer.ids, 2100, 1100,
                                           PathAuthorityGeneration::from_value(1));
    MutationResult result;
    ECMP_REQUIRE(observer.client.add_member(request, result, error));
    ECMP_CHECK(result.outcome == Outcome::STALE_WORKER);
    observer.client.set_worker_boot(synthetic_boot_id(11));
  }

  // The unrelated publisher and its group are unaffected and still authoritative.
  const std::optional<GroupSnapshot> unrelated_after = unrelated.snapshot(snapshot_error);
  ECMP_REQUIRE(unrelated_after.has_value());
  ECMP_CHECK(unrelated_after->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK(unrelated_after->semantic_digest == unrelated_digest);
  {
    SetMemberEnabledRequest request;
    request.authority.epoch = unrelated.epoch;
    request.authority.publisher = publisher_b;
    request.authority.worker_boot = boot_b;
    request.authority.scope = AuthorityScope::for_fabric(unrelated.ids.fabric);
    request.authority.attempt = synthetic_attempt_id(6003);
    request.group = unrelated.group;
    request.member = synthetic_member_id(2000);
    request.enabled = false;
    MutationResult result;
    ECMP_REQUIRE(unrelated.client.set_member_enabled(request, result, error));
    ECMP_CHECK(is_acceptance(result.outcome));
  }

  (void)coordinator.process.terminate();
}

// ---------------------------------------------------------------------------
// REAL coordinator-restart proof: the coordinator process is hard-killed and
// restarted from the same durable store.  Durable definitions survive, live
// authority does not, the epoch advances monotonically, and old epoch traffic is
// rejected.
// ---------------------------------------------------------------------------

ECMP_TEST(test_real_coordinator_restart_preserves_definitions_and_advances_the_epoch) {
  const std::filesystem::path directory = scratch_directory("coordinator-restart");
  const std::filesystem::path store = directory / "governor.store";
  const std::filesystem::path view = directory / "authority.view";
  write_authority_view(view, 8, 1);

  const PublisherId publisher = synthetic_publisher_id(1);
  const WorkerBootId boot = synthetic_boot_id(1);
  Digest assignment_digest;

  Coordinator coordinator;
  std::string error;
  ECMP_REQUIRE(start_coordinator(coordinator, store, view, error));
  ECMP_CHECK_EQ(coordinator.epoch.value(), std::uint64_t{1});

  {
    Session session;
    ECMP_REQUIRE(session.open(coordinator.port, error));
    ECMP_REQUIRE(session.register_publisher(coordinator.port, boot, 3, error));
    CreateGroupRequest request;
    request.authority.epoch = session.epoch;
    request.authority.publisher = publisher;
    request.authority.worker_boot = boot;
    request.authority.scope = AuthorityScope::for_fabric(session.ids.fabric);
    request.authority.attempt = synthetic_attempt_id(7001);
    request.group = synthetic_group_id(1);
    request.key = synthetic_group_key(session.ids);
    request.cost_semantics = synthetic_cost_semantics(session.ids, 1);
    request.hash_domain = session.ids.hash_domain;
    request.provenance = session.ids.provenance;
    request.bucket_count = *BucketCount::make(64);
    request.min_active_members = 2;
    request.members = synthetic_members(session.ids, 4, PathAuthorityGeneration::from_value(1));
    MutationResult result;
    ECMP_REQUIRE(session.client.create_group(request, result, error));
    ECMP_REQUIRE(is_acceptance(result.outcome));
    const std::optional<GroupSnapshot> snapshot = session.snapshot(error);
    ECMP_REQUIRE(snapshot.has_value());
    assignment_digest = snapshot->assignment_digest;
    ECMP_CHECK(snapshot->lifecycle == GroupLifecycle::ACTIVE);
  }

  // Hard kill: the coordinator process dies without any orderly shutdown.
  ECMP_CHECK(coordinator.process.terminate());
  ECMP_CHECK(!coordinator.process.running());

  {
    Coordinator restarted;
    ECMP_REQUIRE(start_coordinator(restarted, store, view, error));
    ECMP_CHECK_EQ(restarted.epoch.value(), std::uint64_t{2});
    ECMP_CHECK_EQ(restarted.recovered, std::uint32_t{1});

    Session session;
    ECMP_REQUIRE(session.open(restarted.port, error));
    ECMP_CHECK_EQ(session.epoch.value(), std::uint64_t{2});

    // Durable definition and desired assignment survive; authority does not.
    const std::optional<GroupSnapshot> recovered = session.snapshot(error);
    ECMP_REQUIRE(recovered.has_value());
    ECMP_CHECK(recovered->lifecycle == GroupLifecycle::REVALIDATION_REQUIRED);
    ECMP_CHECK(recovered->currentness.has(CurrentnessCause::STALE_EPOCH));
    ECMP_CHECK_EQ(recovered->active_member_count(), std::uint32_t{0});
    ECMP_CHECK(recovered->assignment_digest == assignment_digest);

    // Old epoch traffic is rejected before anything else.
    CreateGroupRequest old_epoch;
    old_epoch.authority.epoch = CoordinatorEpoch::from_value(1);
    old_epoch.authority.publisher = publisher;
    old_epoch.authority.worker_boot = boot;
    old_epoch.authority.scope = AuthorityScope::for_fabric(session.ids.fabric);
    old_epoch.authority.attempt = synthetic_attempt_id(7002);
    old_epoch.group = synthetic_group_id(1);
    old_epoch.key = synthetic_group_key(session.ids);
    old_epoch.cost_semantics = synthetic_cost_semantics(session.ids, 1);
    old_epoch.hash_domain = session.ids.hash_domain;
    old_epoch.provenance = session.ids.provenance;
    old_epoch.bucket_count = *BucketCount::make(64);
    old_epoch.min_active_members = 2;
    old_epoch.members = synthetic_members(session.ids, 4, PathAuthorityGeneration::from_value(1));
    // The envelope carries the authority epoch, so a stale client must stamp it.
    session.client.set_epoch(CoordinatorEpoch::from_value(1));
    MutationResult stale_result;
    ECMP_REQUIRE(session.client.create_group(old_epoch, stale_result, error));
    ECMP_CHECK(stale_result.outcome == Outcome::STALE_EPOCH);
    session.client.set_epoch(session.epoch);

    // A boot that never registered in this epoch cannot mutate.
    AddMemberRequest unregistered;
    unregistered.authority.epoch = session.epoch;
    unregistered.authority.publisher = publisher;
    unregistered.authority.worker_boot = synthetic_boot_id(4242);
    unregistered.authority.scope = AuthorityScope::for_fabric(session.ids.fabric);
    unregistered.authority.attempt = synthetic_attempt_id(7003);
    unregistered.group = synthetic_group_id(1);
    unregistered.member = synthetic_member_spec(session.ids, 2100, 1100,
                                                PathAuthorityGeneration::from_value(1));
    MutationResult unregistered_result;
    ECMP_REQUIRE(session.client.add_member(unregistered, unregistered_result, error));
    ECMP_CHECK(unregistered_result.outcome == Outcome::STALE_WORKER ||
               unregistered_result.outcome == Outcome::UNAUTHORIZED);

    // Fresh registration and explicit revalidation restore the same assignment.
    ECMP_REQUIRE(session.register_publisher(restarted.port, boot, 3, error));
    RevalidateGroupRequest revalidate;
    revalidate.authority.epoch = session.epoch;
    revalidate.authority.publisher = publisher;
    revalidate.authority.worker_boot = boot;
    revalidate.authority.scope = AuthorityScope::for_fabric(session.ids.fabric);
    revalidate.authority.attempt = synthetic_attempt_id(7004);
    revalidate.group = synthetic_group_id(1);
    for (std::uint32_t index = 0; index < 4; ++index) {
      MemberRevalidation update;
      update.member = synthetic_member_id(2000 + index);
      update.path_authority = PathAuthorityGeneration::from_value(1);
      revalidate.members.push_back(update);
    }
    MutationResult revalidated;
    ECMP_REQUIRE(session.client.revalidate_group(revalidate, revalidated, error));
    ECMP_REQUIRE(is_acceptance(revalidated.outcome));
    const std::optional<GroupSnapshot> restored = session.snapshot(error);
    ECMP_REQUIRE(restored.has_value());
    ECMP_CHECK(restored->lifecycle == GroupLifecycle::ACTIVE);
    ECMP_CHECK(restored->assignment_digest == assignment_digest);

    // A worker process re-registers against the restarted coordinator and mutates.
    const std::vector<std::string> lines =
        run_worker(restarted.port, "disable", publisher, synthetic_boot_id(31),
                   {"--member-index", "2"});
    ECMP_CHECK(has_line(lines, "outcome=MEMBER_DISABLED"));
    ECMP_CHECK(has_line(lines, "ECMP_WORKER_EXIT code=0"));

    ECMP_CHECK(restarted.process.terminate());
    ECMP_CHECK(!restarted.process.running());
  }

  // A second restart proves strict epoch monotonicity across incarnations.
  {
    Coordinator third;
    ECMP_REQUIRE(start_coordinator(third, store, view, error));
    ECMP_CHECK_EQ(third.epoch.value(), std::uint64_t{3});
    ECMP_CHECK_EQ(third.recovered, std::uint32_t{1});
    ECMP_CHECK(third.process.terminate());
  }
}

// ---------------------------------------------------------------------------
// REAL wire proofs: equal-cost mismatch, member loss and member restore driven
// through separate worker processes.
// ---------------------------------------------------------------------------

ECMP_TEST(test_equal_cost_mismatch_member_loss_and_restore_over_the_wire) {
  const std::filesystem::path directory = scratch_directory("cost-and-loss");
  const std::filesystem::path store = directory / "governor.store";
  const std::filesystem::path view = directory / "authority.view";
  write_authority_view(view, 8, 1);

  Coordinator coordinator;
  std::string error;
  ECMP_REQUIRE(start_coordinator(coordinator, store, view, error));

  const PublisherId publisher = synthetic_publisher_id(1);
  const WorkerBootId boot = synthetic_boot_id(1);

  // A worker process creates the group: four equal-cost members.
  {
    const std::vector<std::string> lines = run_worker(coordinator.port, "create", publisher, boot);
    ECMP_CHECK(has_line(lines, "outcome=CREATED"));
    ECMP_CHECK(has_line(lines, "lifecycle=ACTIVE"));
    ECMP_CHECK(has_line(lines, "active=4"));
    ECMP_CHECK(has_line(lines, "ECMP_WORKER_EXIT code=0"));
  }

  // A different worker incarnation adds a member whose cost is not equal.
  {
    const std::vector<std::string> lines =
        run_worker(coordinator.port, "add", publisher, synthetic_boot_id(2),
                   {"--member-index", "4", "--units", "11"});
    ECMP_CHECK(has_line(lines, "outcome=COST_MISMATCH"));
    ECMP_CHECK(has_line(lines, "condition=COST_VALUE_MISMATCH"));
  }

  // Every worker process owns its own incarnation of the publisher identity.  When
  // a worker exits, the coordinator fences that incarnation, so the groups it owned
  // require explicit revalidation while the durable desired assignment survives.
  Session session;
  ECMP_REQUIRE(session.open(coordinator.port, error));
  ECMP_REQUIRE(session.register_publisher(coordinator.port, session.boot, 3, error));
  {
    const std::optional<GroupSnapshot> fenced = session.snapshot(error);
    ECMP_REQUIRE(fenced.has_value());
    ECMP_CHECK(fenced->lifecycle == GroupLifecycle::REVALIDATION_REQUIRED);
    ECMP_CHECK(fenced->currentness.has(CurrentnessCause::FENCED_PUBLISHER));
    ECMP_CHECK_EQ(fenced->active_member_count(), std::uint32_t{0});
    ECMP_CHECK_EQ(fenced->assignment.owners.size(), std::size_t{64});
  }

  // The upstream feed reports a new Path Authority generation for every path over
  // the wire.  The coordinator applies the fact to its own observation view and the
  // governor re-observes; the claim itself is never treated as an observation.
  for (std::uint32_t index = 0; index < 4; ++index) {
    const std::vector<std::string> lines = run_worker(
        coordinator.port, "notify-path", publisher, synthetic_boot_id(100 + index),
        {"--member-index", std::to_string(index), "--generation", "2"});
    if (!has_line(lines, "ECMP_WORKER_EXIT code=0")) {
      ::ecmp::test::report_failure(__FILE__, __LINE__, "notify worker: " + join(lines));
    }
  }

  // Explicit revalidation through a long-lived session restores the group and the
  // identical bucket map, because the durable desired assignment was never lost.
  {
    RevalidateGroupRequest revalidate;
    revalidate.authority.epoch = session.epoch;
    revalidate.authority.publisher = session.publisher;
    revalidate.authority.worker_boot = session.boot;
    revalidate.authority.scope = AuthorityScope::for_fabric(session.ids.fabric);
    revalidate.authority.attempt = synthetic_attempt_id(8001);
    revalidate.group = synthetic_group_id(1);
    for (std::uint32_t index = 0; index < 4; ++index) {
      MemberRevalidation update;
      update.member = synthetic_member_id(2000 + index);
      update.path_authority = PathAuthorityGeneration::from_value(2);
      revalidate.members.push_back(update);
    }
    MutationResult result;
    if (!session.client.revalidate_group(revalidate, result, error)) {
      ::ecmp::test::report_failure(__FILE__, __LINE__, "revalidate failed: " + error);
    }
    if (!is_acceptance(result.outcome)) {
      ::ecmp::test::report_failure(__FILE__, __LINE__, std::string("expected acceptance, got ") +
                                                          std::string(to_string(result.outcome)));
    }
  }
  const std::optional<GroupSnapshot> restored = session.snapshot(error);
  ECMP_REQUIRE(restored.has_value());
  ECMP_CHECK(restored->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK(restored->currentness.is_current());
  ECMP_CHECK_EQ(restored->active_member_count(), std::uint32_t{4});
  for (const MemberRecord& record : restored->members) {
    ECMP_CHECK_EQ(restored->assignment.owned_bucket_count(record.member), std::uint32_t{16});
  }

  // Member loss: the Path Authority withdraws one exact path while the group is
  // live.  The member becomes ineligible, its buckets are reassigned, the group
  // stays ACTIVE because the threshold still holds, and the unrelated members keep
  // the buckets they already owned.
  {
    PathAuthorityChangeNotice notice;
    notice.epoch = session.epoch;
    notice.publisher = publisher;
    notice.worker_boot = synthetic_boot_id(100);
    notice.path = synthetic_path_id(1002);
    notice.generation = PathAuthorityGeneration::from_value(3);
    MutationResult result;
    if (!session.client.notify_path_authority_change(notice, result, error)) {
      ::ecmp::test::report_failure(__FILE__, __LINE__, "notification failed: " + error);
    }
    ECMP_CHECK(result.outcome == Outcome::REBALANCED);
  }
  const std::optional<GroupSnapshot> after_loss = session.snapshot(error);
  ECMP_REQUIRE(after_loss.has_value());
  ECMP_CHECK(after_loss->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK_EQ(after_loss->active_member_count(), std::uint32_t{3});
  const MemberRecord* lost = after_loss->find_member(synthetic_member_id(2002));
  ECMP_REQUIRE(lost != nullptr);
  ECMP_CHECK(lost->state == MemberState::REVALIDATION_REQUIRED);
  ECMP_CHECK_EQ(after_loss->assignment.owned_bucket_count(lost->member), std::uint32_t{0});
  ECMP_CHECK_EQ(after_loss->assignment.owners.size(), std::size_t{64});
  ECMP_CHECK_EQ(after_loss->assignment_generation.value(),
                restored->assignment_generation.value() + 1);
  for (const MemberRecord& record : after_loss->members) {
    if (record.member == lost->member) {
      continue;
    }
    ECMP_CHECK(after_loss->assignment.owned_bucket_count(record.member) >= std::uint32_t{16});
  }

  // Member restore: revalidate the member with its current binding and get the
  // balanced four-way split back.
  {
    RevalidateGroupRequest revalidate;
    revalidate.authority.epoch = session.epoch;
    revalidate.authority.publisher = session.publisher;
    revalidate.authority.worker_boot = session.boot;
    revalidate.authority.scope = AuthorityScope::for_fabric(session.ids.fabric);
    revalidate.authority.attempt = synthetic_attempt_id(8002);
    revalidate.group = synthetic_group_id(1);
    MemberRevalidation update;
    update.member = synthetic_member_id(2002);
    update.path_authority = PathAuthorityGeneration::from_value(3);
    revalidate.members.push_back(update);
    MutationResult result;
    if (!session.client.revalidate_group(revalidate, result, error)) {
      ::ecmp::test::report_failure(__FILE__, __LINE__, "restore failed: " + error);
    }
    ECMP_CHECK(is_acceptance(result.outcome));
  }
  const std::optional<GroupSnapshot> after_restore = session.snapshot(error);
  ECMP_REQUIRE(after_restore.has_value());
  ECMP_CHECK(after_restore->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK(after_restore->currentness.is_current());
  ECMP_CHECK_EQ(after_restore->active_member_count(), std::uint32_t{4});
  for (const MemberRecord& record : after_restore->members) {
    ECMP_CHECK_EQ(after_restore->assignment.owned_bucket_count(record.member), std::uint32_t{16});
  }

  ECMP_CHECK(coordinator.process.terminate());
}
