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

void usage() {
  std::printf(
      "usage: ecmp-cli <command> [options]\n"
      "\n"
      "commands:\n"
      "  version\n"
      "  store inspect --store FILE\n"
      "  group list --port N [--publisher HEX --boot HEX]\n"
      "  group show --port N --group-seed N [--publisher HEX --boot HEX]\n"
      "  group create --port N --group-seed N [--paths N] [--buckets N] [--min-active N]\n"
      "               [--generation N] [--multipath-set-seed N]\n"
      "  member add|remove|disable|enable|revalidate --port N --group-seed N [...]\n"
      "  rebalance --port N --group-seed N [--paths N]\n"
      "  explain --port N --group-seed N [--member-index N | --bucket N |\n"
      "          --last-rebalance | --authority]\n"
      "  snapshot --port N --group-seed N\n"
      "  diff --port N --group-seed N\n"
      "\n"
      "Synthetic fixtures are derived deterministically from the seeds, so the CLI,\n"
      "the worker and the examples address exactly the same identities.\n");
}

struct Session {
  ecmp::EcmpClient client;
  ecmp::SyntheticIds ids;
  ecmp::ECMPGroupId group;
  ecmp::GroupKey key;
  ecmp::AuthorityContext authority;
  ecmp::CoordinatorEpoch epoch;
};

std::optional<Session> open_session(const std::vector<std::string>& arguments, std::string& error) {
  Session session;
  const std::uint64_t port = option_u64(arguments, "--port", 0);
  if (port == 0 || port > 65535) {
    error = "a coordinator port is required";
    return std::nullopt;
  }
  std::optional<ecmp::EcmpClient> client =
      ecmp::EcmpClient::connect("127.0.0.1", static_cast<std::uint16_t>(port), 5000, error);
  if (!client.has_value()) {
    return std::nullopt;
  }
  session.client = std::move(*client);
  ecmp::HelloResponseBody hello;
  if (!session.client.hello(hello, error)) {
    return std::nullopt;
  }
  session.epoch = hello.epoch;
  const std::uint64_t group_seed = option_u64(arguments, "--group-seed", 1);
  session.ids = ecmp::synthetic_ids(group_seed);
  session.group = ecmp::synthetic_group_id(group_seed);
  session.key = ecmp::synthetic_group_key(session.ids);

  const std::string publisher_text = find_option(arguments, "--publisher").value_or("");
  const std::string boot_text = find_option(arguments, "--boot").value_or("");
  ecmp::PublisherId publisher;
  ecmp::WorkerBootId boot;
  if (!publisher_text.empty() && !boot_text.empty()) {
    const auto parsed_publisher = ecmp::PublisherId::parse(publisher_text);
    const auto parsed_boot = ecmp::WorkerBootId::parse(boot_text);
    if (!parsed_publisher.has_value() || !parsed_boot.has_value()) {
      error = "malformed publisher or boot identity";
      return std::nullopt;
    }
    publisher = *parsed_publisher;
    boot = *parsed_boot;
  } else {
    publisher = ecmp::synthetic_publisher_id(9001);
    boot = ecmp::synthetic_boot_id(9001);
  }
  session.client.set_publisher(publisher);
  session.client.set_worker_boot(boot);

  ecmp::PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = boot;
  registration.scope = ecmp::AuthorityScope::for_fabric(session.ids.fabric);
  registration.capabilities = 3;
  registration.provenance = session.ids.provenance;
  ecmp::RegisterPublisherResponseBody registration_result;
  if (!session.client.register_publisher(registration, registration_result, error)) {
    return std::nullopt;
  }
  if (!ecmp::is_acceptance(registration_result.outcome)) {
    error = std::string("registration rejected: ") +
            std::string(ecmp::to_string(registration_result.outcome));
    return std::nullopt;
  }
  session.authority.epoch = hello.epoch;
  session.authority.publisher = publisher;
  session.authority.worker_boot = boot;
  session.authority.scope = registration.scope;
  return session;
}

void print_result(const ecmp::MutationResult& result) {
  std::printf("outcome=%s\n", std::string(ecmp::to_string(result.outcome)).c_str());
  if (result.group.has_value()) {
    std::printf("group=%s lifecycle=%s currentness=%s\n", result.group->id.to_text().c_str(),
                std::string(ecmp::to_string(result.group->lifecycle)).c_str(),
                result.group->currentness.render().c_str());
    std::printf("membership_generation=%llu assignment_generation=%llu authority_generation=%llu\n",
                static_cast<unsigned long long>(result.group->membership_generation.value()),
                static_cast<unsigned long long>(result.group->assignment_generation.value()),
                static_cast<unsigned long long>(result.group->authority_generation.value()));
    std::printf("declared_members=%u active_members=%u bucket_count=%u\n",
                result.group->declared_members, result.group->active_members,
                result.group->bucket_count.value());
    std::printf("semantic_digest=%s\n", result.group->semantic_digest.to_text().c_str());
  }
  if (result.plan.has_value()) {
    std::printf("plan=%s\n", result.plan->to_text().c_str());
  }
  for (const ecmp::Condition& condition : result.conditions.entries()) {
    std::printf("condition=%s\n", condition.render().c_str());
  }
}

std::vector<ecmp::MemberSpec> members_from(const std::vector<std::string>& arguments,
                                           const ecmp::SyntheticIds& ids) {
  const std::uint64_t paths = option_u64(arguments, "--paths", 4);
  const std::uint64_t generation = option_u64(arguments, "--generation", 1);
  return ecmp::synthetic_members(ids, static_cast<std::uint32_t>(paths),
                                 ecmp::PathAuthorityGeneration::from_value(generation), 1000, 2000);
}

int command_version() {
  std::fputs(ecmp::version_report().c_str(), stdout);
  return 0;
}

int command_store_inspect(const std::vector<std::string>& arguments) {
  const std::optional<std::string> store = find_option(arguments, "--store");
  if (!store.has_value()) {
    std::printf("ECMP_CLI_ERROR detail=store_required\n");
    return 2;
  }
  const ecmp::UnknownPathAuthorityView path_view;
  const ecmp::UnknownMultipathSetView multipath_view;
  ecmp::EcmpGovernor governor(ecmp::GovernorLimits{}, ecmp::CoordinatorEpoch::from_value(1),
                              &path_view, &multipath_view);
  const ecmp::LoadReport report = governor.load(*store);
  if (!report.ok) {
    std::printf("ECMP_CLI_ERROR detail=%s outcome=%s\n", report.detail.c_str(),
                std::string(ecmp::to_string(report.outcome)).c_str());
    return 1;
  }
  std::printf("store=%s stored_epoch=%llu groups=%u recovered=%s\n", store->c_str(),
              static_cast<unsigned long long>(report.stored_epoch.value()), report.groups_loaded,
              report.detail.c_str());
  for (const ecmp::GroupSummary& summary : governor.list_groups()) {
    std::printf("group=%s lifecycle=%s currentness=%s declared=%u active=%u buckets=%u "
                "membership=%llu assignment=%llu semantic_digest=%s\n",
                summary.id.to_text().c_str(),
                std::string(ecmp::to_string(summary.lifecycle)).c_str(),
                summary.currentness.render().c_str(), summary.declared_members,
                summary.active_members, summary.bucket_count.value(),
                static_cast<unsigned long long>(summary.membership_generation.value()),
                static_cast<unsigned long long>(summary.assignment_generation.value()),
                summary.semantic_digest.to_text().c_str());
  }
  std::vector<ecmp::Condition> problems;
  if (!governor.check_invariants(problems)) {
    for (const ecmp::Condition& problem : problems) {
      std::printf("invariant_problem=%s\n", problem.render().c_str());
    }
    return 1;
  }
  std::printf("invariants=ok\n");
  return 0;
}

int command_group(Session& active, const std::vector<std::string>& arguments, std::string& error) {
  const std::string sub = arguments.size() > 1 ? arguments[1] : "";
  if (sub == "list") {
    ecmp::ListGroupsResponseBody body;
    if (!active.client.list_groups(body, error)) {
      std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
      return 1;
    }
    std::printf("groups=%u\n", static_cast<unsigned>(body.groups.size()));
    for (const ecmp::GroupSummary& summary : body.groups) {
      std::printf("group=%s lifecycle=%s declared=%u active=%u membership=%llu assignment=%llu "
                  "semantic_digest=%s\n",
                  summary.id.to_text().c_str(),
                  std::string(ecmp::to_string(summary.lifecycle)).c_str(),
                  summary.declared_members, summary.active_members,
                  static_cast<unsigned long long>(summary.membership_generation.value()),
                  static_cast<unsigned long long>(summary.assignment_generation.value()),
                  summary.semantic_digest.to_text().c_str());
    }
    return 0;
  }
  if (sub == "create") {
    ecmp::CreateGroupRequest request;
    request.authority = active.authority;
    request.group = active.group;
    request.key = active.key;
    request.cost_semantics = ecmp::synthetic_cost_semantics(active.ids, 1);
    request.hash_domain = active.ids.hash_domain;
    request.provenance = active.ids.provenance;
    request.bucket_count = *ecmp::BucketCount::make(
        static_cast<std::uint32_t>(option_u64(arguments, "--buckets", 64)));
    request.min_active_members =
        static_cast<std::uint32_t>(option_u64(arguments, "--min-active", 2));
    request.members = members_from(arguments, active.ids);
    const std::uint64_t multipath_seed = option_u64(arguments, "--multipath-set-seed", 0);
    if (multipath_seed != 0) {
      request.source = ecmp::MembershipSource::MULTIPATH_FABRIC;
      request.multipath_set = ecmp::synthetic_multipath_set_id(multipath_seed);
      request.multipath_generation = ecmp::MultipathSetGeneration::from_value(1);
    }
    ecmp::MutationResult result;
    if (!active.client.create_group(request, result, error)) {
      std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
      return 1;
    }
    print_result(result);
    return 0;
  }
  if (sub == "show") {
    ecmp::SnapshotResponseBody body;
    if (!active.client.snapshot(active.group, body, error)) {
      std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
      return 1;
    }
    std::printf("found=%d\n", body.found ? 1 : 0);
    if (!body.found) {
      return 0;
    }
    std::printf("group=%s lifecycle=%s currentness=%s source=%s\n",
                body.snapshot.id.to_text().c_str(),
                std::string(ecmp::to_string(body.snapshot.lifecycle)).c_str(),
                body.snapshot.currentness.render().c_str(),
                std::string(ecmp::to_string(body.snapshot.source)).c_str());
    std::printf("membership_generation=%llu assignment_generation=%llu authority_generation=%llu "
                "bucket_count=%u min_active=%u\n",
                static_cast<unsigned long long>(body.snapshot.membership_generation.value()),
                static_cast<unsigned long long>(body.snapshot.assignment_generation.value()),
                static_cast<unsigned long long>(body.snapshot.authority_generation.value()),
                body.snapshot.bucket_count.value(), body.snapshot.min_active_members);
    std::printf("canonical_cost=%s semantic_digest=%s assignment_digest=%s membership_digest=%s\n",
                body.snapshot.canonical_cost.to_text().c_str(),
                body.snapshot.semantic_digest.to_text().c_str(),
                body.snapshot.assignment_digest.to_text().c_str(),
                body.snapshot.membership_digest.to_text().c_str());
    for (const ecmp::MemberRecord& record : body.snapshot.members) {
      std::printf("member=%s path=%s state=%s enabled=%d declared=%d path_authority=%llu "
                  "owned_buckets=%u\n",
                  record.member.to_text().c_str(), record.path.to_text().c_str(),
                  std::string(ecmp::to_string(record.state)).c_str(),
                  record.administratively_enabled ? 1 : 0, record.declared ? 1 : 0,
                  static_cast<unsigned long long>(record.path_authority.value()),
                  body.snapshot.assignment.owned_bucket_count(record.member));
    }
    for (std::uint32_t bucket = 0; bucket < body.snapshot.bucket_count.value(); ++bucket) {
      std::printf("bucket=%u owner=%s\n", bucket,
                  body.snapshot.assignment.owners[bucket].is_nil()
                      ? "-"
                      : body.snapshot.assignment.owners[bucket].to_text().c_str());
    }
    return 0;
  }
  std::printf("ECMP_CLI_ERROR detail=unknown_group_command\n");
  return 2;
}

int command_member(Session& active, const std::vector<std::string>& arguments, std::string& error) {
  const std::string sub = arguments.size() > 1 ? arguments[1] : "";
  const std::uint64_t index = option_u64(arguments, "--member-index", 0);
  const ecmp::ECMPMemberId member = ecmp::synthetic_member_id(2000 + index);
  ecmp::MutationResult result;
  bool ok = false;
  if (sub == "add") {
    ecmp::AddMemberRequest request;
    request.authority = active.authority;
    request.group = active.group;
    request.member = ecmp::synthetic_member_spec(
        active.ids, 2000 + index, 1000 + index,
        ecmp::PathAuthorityGeneration::from_value(option_u64(arguments, "--generation", 1)));
    ok = active.client.add_member(request, result, error);
  } else if (sub == "remove") {
    ecmp::RemoveMemberRequest request;
    request.authority = active.authority;
    request.group = active.group;
    request.member = member;
    ok = active.client.remove_member(request, result, error);
  } else if (sub == "disable" || sub == "enable") {
    ecmp::SetMemberEnabledRequest request;
    request.authority = active.authority;
    request.group = active.group;
    request.member = member;
    request.enabled = sub == "enable";
    ok = active.client.set_member_enabled(request, result, error);
  } else if (sub == "revalidate") {
    ecmp::RevalidateGroupRequest request;
    request.authority = active.authority;
    request.group = active.group;
    const std::uint64_t paths = option_u64(arguments, "--paths", 4);
    for (std::uint64_t position = 0; position < paths; ++position) {
      ecmp::MemberRevalidation update;
      update.member = ecmp::synthetic_member_id(2000 + position);
      update.path_authority =
          ecmp::PathAuthorityGeneration::from_value(option_u64(arguments, "--generation", 1));
      request.members.push_back(update);
    }
    ok = active.client.revalidate_group(request, result, error);
  } else {
    std::printf("ECMP_CLI_ERROR detail=unknown_member_command\n");
    return 2;
  }
  if (!ok) {
    std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
    return 1;
  }
  print_result(result);
  return 0;
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
  const std::string command = arguments[0];
  try {
    if (command == "version") {
      return command_version();
    }
    if (command == "store") {
      if (arguments.size() < 2 || arguments[1] != "inspect") {
        std::printf("ECMP_CLI_ERROR detail=unknown_store_command\n");
        return 2;
      }
      return command_store_inspect(arguments);
    }
    std::string error;
    std::optional<Session> session = open_session(arguments, error);
    if (!session.has_value()) {
      std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
      return 1;
    }
    Session& active = *session;

    if (command == "group") {
      return command_group(active, arguments, error);
    }
    if (command == "member") {
      return command_member(active, arguments, error);
    }
    if (command == "rebalance") {
      ecmp::RebalancePlanRequest plan;
      plan.authority = active.authority;
      plan.group = active.group;
      plan.target_members = members_from(arguments, active.ids);
      ecmp::MutationResult planned;
      if (!active.client.plan_rebalance(plan, planned, error)) {
        std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
        return 1;
      }
      print_result(planned);
      if (!planned.plan.has_value()) {
        return 0;
      }
      ecmp::RebalanceCommitRequest commit;
      commit.authority = active.authority;
      commit.group = active.group;
      commit.plan = *planned.plan;
      ecmp::MutationResult committed;
      if (!active.client.commit_rebalance(commit, committed, error)) {
        std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
        return 1;
      }
      print_result(committed);
      return 0;
    }
    if (command == "explain" || command == "diff") {
      ecmp::ExplainRequest request;
      request.group = active.group;
      request.kind = command == "diff" ? ecmp::ExplainKind::LAST_REBALANCE : ecmp::ExplainKind::GROUP;
      if (has_flag(arguments, "--last-rebalance")) {
        request.kind = ecmp::ExplainKind::LAST_REBALANCE;
      } else if (has_flag(arguments, "--authority")) {
        request.kind = ecmp::ExplainKind::AUTHORITY;
      } else if (find_option(arguments, "--member-index").has_value()) {
        request.kind = ecmp::ExplainKind::MEMBER;
        request.member = ecmp::synthetic_member_id(2000 + option_u64(arguments, "--member-index", 0));
      } else if (find_option(arguments, "--bucket").has_value()) {
        request.kind = ecmp::ExplainKind::BUCKET;
        request.bucket = ecmp::BucketId::from_value(
            static_cast<std::uint32_t>(option_u64(arguments, "--bucket", 0)));
      }
      ecmp::ExplainResponseBody body;
      if (!active.client.explain(request, body, error)) {
        std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
        return 1;
      }
      std::printf("found=%d\n", body.found ? 1 : 0);
      std::fputs(body.text.c_str(), stdout);
      return 0;
    }
    if (command == "snapshot") {
      ecmp::SnapshotResponseBody body;
      if (!active.client.snapshot(active.group, body, error)) {
        std::printf("ECMP_CLI_ERROR detail=%s\n", error.c_str());
        return 1;
      }
      std::printf("found=%d semantic_digest=%s assignment_digest=%s membership_digest=%s\n",
                  body.found ? 1 : 0, body.snapshot.semantic_digest.to_text().c_str(),
                  body.snapshot.assignment_digest.to_text().c_str(),
                  body.snapshot.membership_digest.to_text().c_str());
      return 0;
    }
    std::printf("ECMP_CLI_ERROR detail=unknown_command\n");
    return 2;
  } catch (const std::exception& exception) {
    std::printf("ECMP_CLI_ERROR detail=exception:%s\n", exception.what());
    return 1;
  }
}
