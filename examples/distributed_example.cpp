// ECMP Governor 1.0.0 - distributed example.
//
// This example starts real OS processes: one coordinator and one worker.  It then
// hard-kills the worker, proves that its authority is fenced, restarts the
// coordinator from the same durable store, proves that the epoch advanced and that
// the durable definitions survived, and finally registers a fresh worker
// incarnation that revalidates the group.
//
// Everything here is REAL with respect to process lifetime, loopback transport and
// persistence.  Path authority and multipath set facts are supplied by a labelled
// SYNTHETIC file-backed view because no Path Authority or Multipath Fabric runtime
// is available on the build host.

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ecmp/client.hpp"
#include "ecmp/ecmp.hpp"
#include "ecmp/process.hpp"

#ifndef ECMP_COORDINATOR_EXECUTABLE
#define ECMP_COORDINATOR_EXECUTABLE "ecmp_coordinator"
#endif
#ifndef ECMP_WORKER_EXECUTABLE
#define ECMP_WORKER_EXECUTABLE "ecmp_worker"
#endif

namespace {

using namespace ecmp;

int g_failures = 0;

void expect(bool condition, const char* description) {
  if (!condition) {
    ++g_failures;
    std::printf("  FAILED: %s\n", description);
  }
}

std::filesystem::path scratch(const std::string& name) {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / ("ecmp-governor-example-" + name);
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

void write_view(const std::filesystem::path& path, std::uint32_t count, std::uint64_t generation) {
  std::ofstream out(path, std::ios::trunc);
  for (std::uint32_t index = 0; index < count; ++index) {
    out << "authority " << synthetic_path_id(1000 + index).to_text() << ' ' << generation << " 1\n";
  }
}

}  // namespace

int main() {
  const std::filesystem::path directory = scratch("distributed");
  const std::filesystem::path store = directory / "governor.store";
  const std::filesystem::path view = directory / "authority.view";
  write_view(view, 8, 1);

  std::string error;
  Coordinator coordinator;
  if (!start_coordinator(coordinator, store, view, error)) {
    std::printf("coordinator failed to start: %s\n", error.c_str());
    return 1;
  }
  std::printf("step 1: coordinator running on port %u at epoch %llu\n", coordinator.port,
              static_cast<unsigned long long>(coordinator.epoch.value()));

  const PublisherId publisher = synthetic_publisher_id(1);
  const WorkerBootId boot_a1 = synthetic_boot_id(1);

  // Real worker process: creates the governed group and holds its session open.
  LocalProcess::Options options;
  options.executable = ECMP_WORKER_EXECUTABLE;
  options.arguments = {"--port",          std::to_string(coordinator.port),
                       "--scenario",      "hold",
                       "--publisher",     publisher.to_text(),
                       "--boot",          boot_a1.to_text(),
                       "--group-seed",    "1",
                       "--paths",         "4",
                       "--buckets",       "64",
                       "--min-active",    "2",
                       "--path-seed-base", "1000"};
  std::optional<LocalProcess> worker = LocalProcess::spawn(options, error);
  if (!worker.has_value()) {
    std::printf("worker failed to start: %s\n", error.c_str());
    return 1;
  }
  bool holding = false;
  std::string line;
  while (worker->read_line(line)) {
    if (line.find("ECMP_WORKER_RESULT") != std::string::npos) {
      std::printf("step 2: %s\n", line.c_str());
    }
    if (line.find("ECMP_WORKER_HOLDING") != std::string::npos) {
      holding = true;
      break;
    }
  }
  expect(holding, "worker created the group and is holding its session");
  expect(worker->running(), "worker process is alive");

  // Independent client for observation and later revalidation.
  std::optional<EcmpClient> client =
      EcmpClient::connect("127.0.0.1", coordinator.port, 5000, error);
  if (!client.has_value()) {
    std::printf("client failed to connect: %s\n", error.c_str());
    return 1;
  }
  HelloResponseBody hello;
  expect(client->hello(hello, error), "hello");
  client->set_publisher(synthetic_publisher_id(7001));
  client->set_worker_boot(synthetic_boot_id(7001));
  {
    PublisherRegistration registration;
    registration.publisher = synthetic_publisher_id(7001);
    registration.worker_boot = synthetic_boot_id(7001);
    registration.scope = AuthorityScope::for_fabric(synthetic_ids(1).fabric);
    registration.capabilities = 3;
    registration.provenance = synthetic_ids(1).provenance;
    RegisterPublisherResponseBody body;
    expect(client->register_publisher(registration, body, error) && is_acceptance(body.outcome),
           "observer registration");
  }

  Digest assignment_digest;
  {
    SnapshotResponseBody snapshot;
    expect(client->snapshot(synthetic_group_id(1), snapshot, error), "snapshot request");
    expect(snapshot.found, "group exists");
    expect(snapshot.snapshot.lifecycle == GroupLifecycle::ACTIVE, "group is ACTIVE");
    assignment_digest = snapshot.snapshot.assignment_digest;
  }

  // Real OS process termination.
  expect(worker->terminate(), "worker termination");
  expect(!worker->running(), "worker is dead");
  std::printf("step 3: worker process terminated\n");

  // The coordinator fences the dead incarnation: its groups require revalidation.
  bool fenced = false;
  for (int attempt = 0; attempt < 4000 && !fenced; ++attempt) {
    ExplainRequest request;
    request.group = synthetic_group_id(1);
    request.kind = ExplainKind::AUTHORITY;
    ExplainResponseBody body;
    if (client->explain(request, body, error) &&
        body.text.find("subject=authority_current observed=0") != std::string::npos) {
      fenced = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  expect(fenced, "coordinator fenced the dead worker incarnation");
  {
    SnapshotResponseBody snapshot;
    expect(client->snapshot(synthetic_group_id(1), snapshot, error), "snapshot request");
    expect(snapshot.snapshot.lifecycle == GroupLifecycle::REVALIDATION_REQUIRED,
           "group requires revalidation");
    expect(snapshot.snapshot.assignment_digest == assignment_digest,
           "durable desired assignment survived the worker death");
  }

  // A hard coordinator restart: durable definitions survive, live authority does not.
  expect(coordinator.process.terminate(), "coordinator termination");
  Coordinator restarted;
  if (!start_coordinator(restarted, store, view, error)) {
    std::printf("coordinator restart failed: %s\n", error.c_str());
    return 1;
  }
  expect(restarted.epoch.value() == coordinator.epoch.value() + 1, "epoch advanced monotonically");
  expect(restarted.recovered == 1, "durable group recovered");
  std::printf("step 4: coordinator restarted at epoch %llu with %u recovered group(s)\n",
              static_cast<unsigned long long>(restarted.epoch.value()), restarted.recovered);

  // Fresh worker incarnation for the same publisher identity, and revalidation.
  std::optional<EcmpClient> fresh = EcmpClient::connect("127.0.0.1", restarted.port, 5000, error);
  if (!fresh.has_value()) {
    std::printf("reconnect failed: %s\n", error.c_str());
    return 1;
  }
  expect(fresh->hello(hello, error), "hello after restart");
  fresh->set_publisher(publisher);
  fresh->set_worker_boot(synthetic_boot_id(11));
  {
    PublisherRegistration registration;
    registration.publisher = publisher;
    registration.worker_boot = synthetic_boot_id(11);
    registration.scope = AuthorityScope::for_fabric(synthetic_ids(1).fabric);
    registration.capabilities = 3;
    registration.provenance = synthetic_ids(1).provenance;
    RegisterPublisherResponseBody body;
    expect(fresh->register_publisher(registration, body, error) && is_acceptance(body.outcome),
           "fresh boot registration");
  }
  {
    RevalidateGroupRequest request;
    request.authority.epoch = hello.epoch;
    request.authority.publisher = publisher;
    request.authority.worker_boot = synthetic_boot_id(11);
    request.authority.scope = AuthorityScope::for_fabric(synthetic_ids(1).fabric);
    request.authority.attempt = synthetic_attempt_id(4001);
    request.group = synthetic_group_id(1);
    for (std::uint32_t index = 0; index < 4; ++index) {
      MemberRevalidation update;
      update.member = synthetic_member_id(2000 + index);
      update.path_authority = PathAuthorityGeneration::from_value(1);
      request.members.push_back(update);
    }
    MutationResult result;
    expect(fresh->revalidate_group(request, result, error), "revalidation completed");
    expect(is_acceptance(result.outcome), "revalidation accepted");
  }
  {
    SnapshotResponseBody snapshot;
    expect(fresh->snapshot(synthetic_group_id(1), snapshot, error), "snapshot request");
    expect(snapshot.snapshot.lifecycle == GroupLifecycle::ACTIVE, "group is ACTIVE again");
    expect(snapshot.snapshot.assignment_digest == assignment_digest,
           "the identical bucket map was restored without churn");
  }
  std::printf("step 5: fresh worker incarnation revalidated the group\n");

  expect(restarted.process.terminate(), "final coordinator termination");
  const std::filesystem::path cleanup = directory;
  std::error_code remove_error;
  std::filesystem::remove_all(cleanup, remove_error);
  if (g_failures != 0) {
    std::printf("distributed example failed: %d\n", g_failures);
    return 1;
  }
  std::printf("distributed example completed successfully\n");
  return 0;
}
