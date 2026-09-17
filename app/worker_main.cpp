#include <cstdint>
#include <cstdio>
#include <exception>
#include <optional>
#include <string>
#include <vector>

#include "ecmp/client.hpp"
#include "ecmp/ecmp.hpp"
#include "ecmp/version.hpp"
#include "support.hpp"

namespace {

using ecmp::app::find_option;
using ecmp::app::has_flag;
using ecmp::app::option_u64;

struct WorkerOptions {
  std::uint16_t port = 0;
  std::string scenario;
  std::uint64_t publisher_seed = 0;
  std::uint64_t boot_seed = 0;
  std::string publisher_text;
  std::string boot_text;
  std::uint64_t group_seed = 1;
  std::uint64_t paths = 4;
  std::uint64_t buckets = 64;
  std::uint64_t min_active = 2;
  std::uint64_t path_seed_base = 1000;
  std::uint64_t member_seed_base = 2000;
  std::uint64_t generation = 1;
  std::uint64_t member_index = 0;
  std::uint64_t multipath_set_seed = 0;
  std::uint64_t capabilities = 3;
  std::int64_t units = 10;
  bool group_scope = false;
  bool hold = false;
};

void usage() {
  std::printf(
      "usage: ecmp_worker --port N --scenario NAME [--publisher HEX] [--boot HEX]\n"
      "                   [--group-seed N] [--paths N] [--buckets N] [--min-active N]\n"
      "                   [--path-seed-base N] [--member-seed-base N] [--generation N]\n"
      "                   [--member-index N] [--multipath-set-seed N] [--capabilities N]\n"
      "                   [--group-scope] [--hold]\n"
      "scenarios: register create hold add remove disable enable revalidate snapshot\n"
      "           stale-register notify-path replay\n");
}

std::optional<ecmp::PublisherId> parse_publisher(const WorkerOptions& options) {
  if (!options.publisher_text.empty()) {
    return ecmp::PublisherId::parse(options.publisher_text);
  }
  return ecmp::synthetic_publisher_id(options.publisher_seed);
}

std::optional<ecmp::WorkerBootId> parse_boot(const WorkerOptions& options) {
  if (!options.boot_text.empty()) {
    return ecmp::WorkerBootId::parse(options.boot_text);
  }
  return ecmp::synthetic_boot_id(options.boot_seed);
}

void print_result(const std::string& scenario, std::uint32_t step, const ecmp::MutationResult& result) {
  std::printf("ECMP_WORKER_RESULT scenario=%s step=%u outcome=%s", scenario.c_str(), step,
              std::string(ecmp::to_string(result.outcome)).c_str());
  if (result.group.has_value()) {
    std::printf(" lifecycle=%s membership=%llu assignment=%llu authority=%llu active=%u declared=%u digest=%s",
                std::string(ecmp::to_string(result.group->lifecycle)).c_str(),
                static_cast<unsigned long long>(result.group->membership_generation.value()),
                static_cast<unsigned long long>(result.group->assignment_generation.value()),
                static_cast<unsigned long long>(result.group->authority_generation.value()),
                result.group->active_members, result.group->declared_members,
                result.group->semantic_digest.to_text().c_str());
  }
  if (result.plan.has_value()) {
    std::printf(" plan=%s", result.plan->to_text().c_str());
  }
  if (!result.conditions.empty()) {
    std::printf(" condition=%s", std::string(ecmp::to_string(result.conditions.entries().front().code)).c_str());
  }
  std::printf("\n");
  std::fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  if (arguments.empty() || has_flag(arguments, "--help")) {
    usage();
    return arguments.empty() ? 2 : 0;
  }
  WorkerOptions options;
  options.scenario = find_option(arguments, "--scenario").value_or("register");
  options.port = static_cast<std::uint16_t>(option_u64(arguments, "--port", 0));
  options.publisher_seed = option_u64(arguments, "--publisher-seed", 1);
  options.boot_seed = option_u64(arguments, "--boot-seed", 1);
  options.publisher_text = find_option(arguments, "--publisher").value_or("");
  options.boot_text = find_option(arguments, "--boot").value_or("");
  options.group_seed = option_u64(arguments, "--group-seed", 1);
  options.paths = option_u64(arguments, "--paths", 4);
  options.buckets = option_u64(arguments, "--buckets", 64);
  options.min_active = option_u64(arguments, "--min-active", 2);
  options.path_seed_base = option_u64(arguments, "--path-seed-base", 1000);
  options.member_seed_base = option_u64(arguments, "--member-seed-base", 2000);
  options.generation = option_u64(arguments, "--generation", 1);
  options.member_index = option_u64(arguments, "--member-index", 0);
  options.multipath_set_seed = option_u64(arguments, "--multipath-set-seed", 0);
  options.capabilities = option_u64(arguments, "--capabilities", 3);
  options.units = static_cast<std::int64_t>(option_u64(arguments, "--units", 10));
  options.group_scope = has_flag(arguments, "--group-scope");
  // The hold scenario always holds: the flag exists for the other scenarios.
  options.hold = has_flag(arguments, "--hold") || options.scenario == "hold";

  try {
    const std::optional<ecmp::PublisherId> publisher = parse_publisher(options);
    const std::optional<ecmp::WorkerBootId> boot = parse_boot(options);
    if (!publisher.has_value() || !boot.has_value()) {
      std::printf("ECMP_WORKER_ERROR detail=malformed_publisher_identity\n");
      return 2;
    }
    std::string error;
    std::optional<ecmp::EcmpClient> client =
        ecmp::EcmpClient::connect("127.0.0.1", options.port, 5000, error);
    if (!client.has_value()) {
      std::printf("ECMP_WORKER_ERROR detail=connect_failed:%s\n", error.c_str());
      return 3;
    }
    ecmp::HelloResponseBody hello;
    if (!client->hello(hello, error)) {
      std::printf("ECMP_WORKER_ERROR detail=hello_failed:%s\n", error.c_str());
      return 3;
    }
    client->set_publisher(*publisher);
    client->set_worker_boot(*boot);

    const ecmp::SyntheticIds ids = ecmp::synthetic_ids(options.group_seed);
    ecmp::GroupKey key = ecmp::synthetic_group_key(ids);
    const ecmp::ECMPGroupId group_id = ecmp::synthetic_group_id(options.group_seed);
    ecmp::AuthorityScope scope = options.group_scope ? ecmp::AuthorityScope::for_group(group_id)
                                                     : ecmp::AuthorityScope::for_fabric(ids.fabric);
    ecmp::PublisherRegistration registration;
    registration.publisher = *publisher;
    registration.worker_boot = *boot;
    registration.scope = scope;
    registration.capabilities = static_cast<std::uint32_t>(options.capabilities);
    registration.provenance = ids.provenance;

    ecmp::RegisterPublisherResponseBody registration_result;
    if (!client->register_publisher(registration, registration_result, error)) {
      std::printf("ECMP_WORKER_ERROR detail=register_failed:%s\n", error.c_str());
      return 3;
    }
    std::printf("ECMP_WORKER_REGISTER outcome=%s",
                std::string(ecmp::to_string(registration_result.outcome)).c_str());
    if (!registration_result.conditions.empty()) {
      std::printf(" condition=%s",
                  std::string(ecmp::to_string(registration_result.conditions.entries().front().code))
                      .c_str());
    }
    std::printf("\n");
    std::fflush(stdout);
    if (options.scenario == "stale-register" || options.scenario == "register") {
      std::printf("ECMP_WORKER_EXIT code=0\n");
      std::fflush(stdout);
      return 0;
    }
    if (!ecmp::is_acceptance(registration_result.outcome)) {
      std::printf("ECMP_WORKER_EXIT code=3\n");
      std::fflush(stdout);
      return 3;
    }

    ecmp::AuthorityContext authority;
    authority.epoch = hello.epoch;
    authority.publisher = *publisher;
    authority.worker_boot = *boot;
    authority.scope = scope;

    const auto generation = ecmp::PathAuthorityGeneration::from_value(options.generation);
    const ecmp::MultipathSetId multipath_set =
        options.multipath_set_seed == 0 ? ecmp::MultipathSetId{}
                                        : ecmp::synthetic_multipath_set_id(options.multipath_set_seed);

    if (options.scenario == "create" || options.scenario == "hold" ||
        options.scenario == "snapshot" || options.scenario == "replay" ||
        options.scenario == "add" || options.scenario == "remove" ||
        options.scenario == "disable" || options.scenario == "enable") {
      ecmp::CreateGroupRequest request;
      request.authority = authority;
      request.group = group_id;
      request.key = key;
      request.source = multipath_set.is_nil() ? ecmp::MembershipSource::DIRECT_PATH_SET
                                              : ecmp::MembershipSource::MULTIPATH_FABRIC;
      request.multipath_set = multipath_set;
      request.multipath_generation = ecmp::MultipathSetGeneration::from_value(1);
      request.cost_semantics = ecmp::synthetic_cost_semantics(ids, 1);
      request.hash_domain = ids.hash_domain;
      request.bucket_count = *ecmp::BucketCount::make(static_cast<std::uint32_t>(options.buckets));
      request.min_active_members = static_cast<std::uint32_t>(options.min_active);
      request.members = ecmp::synthetic_members(ids, static_cast<std::uint32_t>(options.paths),
                                                generation, options.path_seed_base,
                                                options.member_seed_base, options.units);
      request.provenance = ids.provenance;
      ecmp::MutationResult result;
      if (!client->create_group(request, result, error)) {
        std::printf("ECMP_WORKER_ERROR detail=create_failed:%s\n", error.c_str());
        return 3;
      }
      print_result(options.scenario, 1, result);
      if (options.scenario == "replay") {
        const ecmp::MutationAttemptId attempt = ecmp::synthetic_attempt_id(7777);
        client->set_attempt(attempt);
        ecmp::MutationResult first;
        if (!client->create_group(request, first, error)) {
          std::printf("ECMP_WORKER_ERROR detail=replay_failed:%s\n", error.c_str());
          return 3;
        }
        print_result(options.scenario, 2, first);
        ecmp::MutationResult second;
        if (!client->create_group(request, second, error)) {
          std::printf("ECMP_WORKER_ERROR detail=replay_failed:%s\n", error.c_str());
          return 3;
        }
        print_result(options.scenario, 3, second);
      }
      if (options.scenario == "snapshot") {
        ecmp::SnapshotResponseBody snapshot;
        if (!client->snapshot(group_id, snapshot, error)) {
          std::printf("ECMP_WORKER_ERROR detail=snapshot_failed:%s\n", error.c_str());
          return 3;
        }
        std::printf("ECMP_WORKER_SNAPSHOT found=%d lifecycle=%s membership=%llu assignment=%llu "
                    "semantic_digest=%s assignment_digest=%s\n",
                    snapshot.found ? 1 : 0,
                    std::string(ecmp::to_string(snapshot.snapshot.lifecycle)).c_str(),
                    static_cast<unsigned long long>(snapshot.snapshot.membership_generation.value()),
                    static_cast<unsigned long long>(snapshot.snapshot.assignment_generation.value()),
                    snapshot.snapshot.semantic_digest.to_text().c_str(),
                    snapshot.snapshot.assignment_digest.to_text().c_str());
        std::fflush(stdout);
      }
    }

    if (options.scenario == "add") {
      ecmp::AddMemberRequest request;
      request.authority = authority;
      request.group = group_id;
      request.member = ecmp::synthetic_member_spec(
          ids, options.member_seed_base + options.member_index,
          options.path_seed_base + options.member_index, generation, options.units);
      ecmp::MutationResult result;
      if (!client->add_member(request, result, error)) {
        std::printf("ECMP_WORKER_ERROR detail=add_failed:%s\n", error.c_str());
        return 3;
      }
      print_result(options.scenario, 1, result);
    } else if (options.scenario == "remove" || options.scenario == "disable" ||
               options.scenario == "enable") {
      const ecmp::ECMPMemberId member =
          ecmp::synthetic_member_id(options.member_seed_base + options.member_index);
      ecmp::MutationResult result;
      bool ok = false;
      if (options.scenario == "remove") {
        ecmp::RemoveMemberRequest request;
        request.authority = authority;
        request.group = group_id;
        request.member = member;
        ok = client->remove_member(request, result, error);
      } else {
        ecmp::SetMemberEnabledRequest request;
        request.authority = authority;
        request.group = group_id;
        request.member = member;
        request.enabled = options.scenario == "enable";
        ok = client->set_member_enabled(request, result, error);
      }
      if (!ok) {
        std::printf("ECMP_WORKER_ERROR detail=mutation_failed:%s\n", error.c_str());
        return 3;
      }
      print_result(options.scenario, 1, result);
    } else if (options.scenario == "revalidate") {
      ecmp::RevalidateGroupRequest request;
      request.authority = authority;
      request.group = group_id;
      for (std::uint64_t index = 0; index < options.paths; ++index) {
        ecmp::MemberRevalidation update;
        update.member = ecmp::synthetic_member_id(options.member_seed_base + index);
        update.path_authority = generation;
        request.members.push_back(update);
      }
      ecmp::MutationResult result;
      if (!client->revalidate_group(request, result, error)) {
        std::printf("ECMP_WORKER_ERROR detail=revalidate_failed:%s\n", error.c_str());
        return 3;
      }
      print_result(options.scenario, 1, result);
    } else if (options.scenario == "notify-path") {
      ecmp::PathAuthorityChangeNotice notice;
      notice.path = ecmp::synthetic_path_id(options.path_seed_base + options.member_index);
      notice.generation = generation;
      ecmp::MutationResult result;
      if (!client->notify_path_authority_change(notice, result, error)) {
        std::printf("ECMP_WORKER_ERROR detail=notify_failed:%s\n", error.c_str());
        return 3;
      }
      print_result(options.scenario, 1, result);
    }

    if (options.hold) {
      std::printf("ECMP_WORKER_HOLDING boot=%s\n", boot->to_text().c_str());
      std::fflush(stdout);
      // The worker blocks until the coordinator fences it or the connection ends.
      // There is no polling, no timer and no guess: the coordinator's fence
      // notice is what releases it.
      const bool fenced = client->wait_for_fence(error);
      std::printf("ECMP_WORKER_HELD_EXIT fenced=%d\n", fenced ? 1 : 0);
      std::fflush(stdout);
    }

    client->close();
    std::printf("ECMP_WORKER_EXIT code=0\n");
    std::fflush(stdout);
    return 0;
  } catch (const std::exception& exception) {
    std::printf("ECMP_WORKER_ERROR detail=exception:%s\n", exception.what());
    std::fflush(stdout);
    return 2;
  }
}
