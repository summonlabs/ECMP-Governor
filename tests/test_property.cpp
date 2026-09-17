#include <algorithm>
#include <atomic>
#include <cstdint>
#include <map>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "ecmp/ecmp.hpp"
#include "test_framework.hpp"

namespace {

using namespace ecmp;

class AlwaysAuthorized final : public IPathAuthorityView {
 public:
  [[nodiscard]] std::optional<PathAuthorityObservation> observe(
      const PathId&) const override {
    PathAuthorityObservation observation;
    observation.generation = PathAuthorityGeneration::from_value(1);
    observation.authorized = true;
    return observation;
  }
};

struct Harness {
  AlwaysAuthorized view;
  GovernorLimits limits;
  SyntheticIds ids = synthetic_ids(1);
  PublisherId publisher = synthetic_publisher_id(1);
  WorkerBootId boot = synthetic_boot_id(1);
  std::unique_ptr<EcmpGovernor> governor;
  std::uint64_t attempts = 0;

  explicit Harness(GovernorLimits limits_in = GovernorLimits{})
      : limits(limits_in),
        governor(std::make_unique<EcmpGovernor>(limits_in, CoordinatorEpoch::from_value(1), &view)) {
    PublisherRegistration registration;
    registration.publisher = publisher;
    registration.worker_boot = boot;
    registration.scope = AuthorityScope::for_fabric(ids.fabric);
    registration.capabilities = 3;
    registration.provenance = ids.provenance;
    ConditionList conditions(limits.max_explanation_entries);
    const Outcome outcome = governor->register_publisher(governor->epoch(), registration, conditions);
    if (!is_acceptance(outcome)) {
      throw std::runtime_error("registration failed");
    }
  }

  AuthorityContext authority() {
    AuthorityContext context;
    context.epoch = governor->epoch();
    context.publisher = publisher;
    context.worker_boot = boot;
    context.scope = AuthorityScope::for_fabric(ids.fabric);
    ++attempts;
    context.attempt = synthetic_attempt_id(100000 + attempts);
    return context;
  }

  Outcome create(std::uint64_t seed, std::uint32_t members, std::uint32_t buckets) {
    CreateGroupRequest request;
    request.authority = authority();
    request.group = synthetic_group_id(seed % 50);
    request.key = synthetic_group_key(synthetic_ids(seed % 50));
    request.key.fabric = ids.fabric;
    request.cost_semantics = synthetic_cost_semantics(synthetic_ids(seed % 50), 1);
    request.hash_domain = synthetic_ids(seed % 50).hash_domain;
    request.provenance = synthetic_ids(seed % 50).provenance;
    request.bucket_count = *BucketCount::make(buckets);
    request.min_active_members = 1;
    request.members = synthetic_members(synthetic_ids(seed % 50), members,
                                        PathAuthorityGeneration::from_value(1));
    return governor->create_group(request).outcome;
  }

  Outcome mutate(std::uint64_t seed, std::uint32_t op) {
    const SyntheticIds group_ids = synthetic_ids(seed % 50);
    const ECMPGroupId group = synthetic_group_id(seed % 50);
    const std::uint32_t index = static_cast<std::uint32_t>(op % 8);
    switch (op % 5) {
      case 0: {
        AddMemberRequest request;
        request.authority = authority();
        request.group = group;
        request.member = synthetic_member_spec(group_ids, 2000 + index, 1000 + index,
                                               PathAuthorityGeneration::from_value(1));
        return governor->add_member(request).outcome;
      }
      case 1: {
        RemoveMemberRequest request;
        request.authority = authority();
        request.group = group;
        request.member = synthetic_member_id(2000 + index);
        return governor->remove_member(request).outcome;
      }
      case 2: {
        SetMemberEnabledRequest request;
        request.authority = authority();
        request.group = group;
        request.member = synthetic_member_id(2000 + index);
        request.enabled = (op % 2) == 0;
        return governor->set_member_enabled(request).outcome;
      }
      case 3: {
        MembershipSetRequest request;
        request.authority = authority();
        request.group = group;
        const std::uint32_t count = 1 + (index % 6);
        request.members = synthetic_members(group_ids, count, PathAuthorityGeneration::from_value(1));
        return governor->apply_membership_set(request).outcome;
      }
      default: {
        RevalidateGroupRequest request;
        request.authority = authority();
        request.group = group;
        for (std::uint32_t position = 0; position < 8; ++position) {
          MemberRevalidation update;
          update.member = synthetic_member_id(2000 + position);
          update.path_authority = PathAuthorityGeneration::from_value(1);
          request.members.push_back(update);
        }
        return governor->revalidate_group(request).outcome;
      }
    }
  }
};

}  // namespace

// --- randomized property schedules -----------------------------------------

ECMP_TEST(test_randomized_schedules_preserve_every_invariant) {
  for (std::uint64_t seed = 1; seed <= 12; ++seed) {
    Harness harness;
    std::mt19937_64 random(0x9E3779B97F4A7C15ull * seed);
    for (std::uint32_t group = 0; group < 8; ++group) {
      const Outcome outcome = harness.create(group + 1, 2 + (group % 5), 16);
      ECMP_CHECK(is_acceptance(outcome));
    }
    for (int step = 0; step < 300; ++step) {
      const std::uint64_t pick = random();
      const Outcome outcome = harness.mutate(pick % 50 + 1, static_cast<std::uint32_t>(pick >> 8));
      // Any outcome is legal as long as it is a known structured result.
      ECMP_CHECK(static_cast<std::uint32_t>(outcome) >= 1);
      ECMP_CHECK(static_cast<std::uint32_t>(outcome) <= 66);
      std::vector<Condition> problems;
      if (!harness.governor->check_invariants(problems)) {
        for (const Condition& problem : problems) {
          ::ecmp::test::report_failure(__FILE__, __LINE__, "invariant: " + problem.render());
        }
      }
    }
    // Every group must still be fully explainable and internally consistent.
    for (const GroupSummary& summary : harness.governor->list_groups()) {
      const std::optional<GroupSnapshot> snapshot = harness.governor->snapshot(summary.id);
      ECMP_REQUIRE(snapshot.has_value());
      if (snapshot->lifecycle == GroupLifecycle::ACTIVE ||
          snapshot->lifecycle == GroupLifecycle::DEGRADED) {
        ECMP_CHECK(check_assignment(snapshot->assignment, snapshot->active_members) ==
                   AssignmentDefect::NONE);
      }
    }
  }
}

ECMP_TEST(test_atomic_declaration_is_independent_of_input_order) {
  // The same semantic declaration presented in different orders must produce an
  // identical canonical member list, bucket map, digest and generations.
  std::map<std::string, GroupSummary> by_order;
  for (int permutation = 0; permutation < 6; ++permutation) {
    Harness harness;
    CreateGroupRequest request;
    request.authority = harness.authority();
    request.group = synthetic_group_id(1);
    request.key = synthetic_group_key(harness.ids);
    request.cost_semantics = synthetic_cost_semantics(harness.ids, 1);
    request.hash_domain = harness.ids.hash_domain;
    request.provenance = harness.ids.provenance;
    request.bucket_count = *BucketCount::make(32);
    request.min_active_members = 1;
    request.members = synthetic_members(harness.ids, 5, PathAuthorityGeneration::from_value(1));
    std::vector<MemberSpec> shuffled = request.members;
    std::mt19937_64 random(static_cast<std::uint64_t>(permutation) + 7);
    std::shuffle(shuffled.begin(), shuffled.end(), random);
    request.members = shuffled;
    const MutationResult result = harness.governor->create_group(request);
    ECMP_REQUIRE(is_acceptance(result.outcome));
    const std::optional<GroupSnapshot> snapshot = harness.governor->snapshot(request.group);
    ECMP_REQUIRE(snapshot.has_value());
    by_order[snapshot->semantic_digest.to_text()] = summarize(*snapshot);
  }
  ECMP_CHECK_EQ(by_order.size(), std::size_t{1});
  const GroupSummary& summary = by_order.begin()->second;
  ECMP_CHECK_EQ(summary.membership_generation.value(), std::uint64_t{1});
  ECMP_CHECK_EQ(summary.assignment_generation.value(), std::uint64_t{1});
}

// --- deterministic races ----------------------------------------------------

ECMP_TEST(test_conflicting_mutations_with_the_same_expected_generation_resolve_once) {
  for (int repetition = 0; repetition < 20; ++repetition) {
    Harness harness;
    ECMP_REQUIRE(is_acceptance(harness.create(1, 3, 32)));

    std::atomic<int> accepted{0};
    std::atomic<int> stale{0};
    std::atomic<int> other{0};
    const auto worker = [&](std::uint32_t index) {
      AddMemberRequest request;
      request.authority = harness.authority();
      request.authority.expected_membership = MembershipGeneration::from_value(1);
      request.group = synthetic_group_id(1);
      request.member = synthetic_member_spec(harness.ids, 2500 + index, 1500 + index,
                                             PathAuthorityGeneration::from_value(1));
      const Outcome outcome = harness.governor->add_member(request).outcome;
      if (is_acceptance(outcome)) {
        ++accepted;
      } else if (outcome == Outcome::STALE_GROUP_GENERATION) {
        ++stale;
      } else {
        ++other;
      }
    };
    std::thread first([&]() { worker(0); });
    std::thread second([&]() { worker(1); });
    first.join();
    second.join();
    // Exactly one mutation observes membership generation 1 and commits; the other
    // is deterministically rejected as stale.  Nothing else may happen.
    ECMP_CHECK_EQ(accepted.load(), 1);
    ECMP_CHECK_EQ(stale.load(), 1);
    ECMP_CHECK_EQ(other.load(), 0);
    std::vector<Condition> problems;
    ECMP_CHECK(harness.governor->check_invariants(problems));
  }
}

ECMP_TEST(test_invalidation_racing_a_rebalance_commit_is_always_legal) {
  for (int repetition = 0; repetition < 20; ++repetition) {
    Harness harness;
    ECMP_REQUIRE(is_acceptance(harness.create(1, 4, 32)));

    RebalancePlanRequest plan;
    plan.authority = harness.authority();
    plan.group = synthetic_group_id(1);
    plan.target_members = synthetic_members(harness.ids, 3, PathAuthorityGeneration::from_value(1));
    const MutationResult planned = harness.governor->plan_rebalance(plan);
    ECMP_REQUIRE(is_acceptance(planned.outcome));
    ECMP_REQUIRE(planned.plan.has_value());

    std::atomic<int> committed{0};
    std::atomic<int> stale{0};
    std::thread commit([&]() {
      RebalanceCommitRequest request;
      request.authority = harness.authority();
      request.group = synthetic_group_id(1);
      request.plan = *planned.plan;
      const Outcome outcome = harness.governor->commit_rebalance(request).outcome;
      if (outcome == Outcome::REBALANCED) {
        ++committed;
      } else if (outcome == Outcome::STALE_PLAN || outcome == Outcome::NO_PENDING_PLAN) {
        ++stale;
      }
    });
    std::thread invalidate([&]() {
      PathAuthorityChangeNotice notice;
      notice.epoch = harness.governor->epoch();
      notice.publisher = harness.publisher;
      notice.worker_boot = harness.boot;
      notice.path = synthetic_path_id(1000);
      notice.generation = PathAuthorityGeneration::from_value(2);
      (void)harness.governor->notify_path_authority_change(notice);
    });
    commit.join();
    invalidate.join();

    // Whatever the interleaving, the committed state is either the plan applied or
    // the invalidation applied, never a mixture, and always structurally valid.
    ECMP_CHECK(committed.load() + stale.load() == 1);
    std::vector<Condition> problems;
    if (!harness.governor->check_invariants(problems)) {
      for (const Condition& problem : problems) {
        ::ecmp::test::report_failure(__FILE__, __LINE__, "invariant: " + problem.render());
      }
    }
    const std::optional<GroupSnapshot> snapshot = harness.governor->snapshot(synthetic_group_id(1));
    ECMP_REQUIRE(snapshot.has_value());
    ECMP_CHECK_EQ(snapshot->assignment.owners.size(), std::size_t{32});
  }
}

ECMP_TEST(test_concurrent_queries_and_independent_group_mutations) {
  Harness harness;
  for (std::uint32_t group = 0; group < 8; ++group) {
    ECMP_REQUIRE(is_acceptance(harness.create(group + 1, 3, 32)));
  }
  std::atomic<int> failures{0};
  const auto mutator = [&](std::uint32_t group) {
    for (int step = 0; step < 40; ++step) {
      const Outcome outcome =
          harness.mutate(group + 1, static_cast<std::uint32_t>(step % 8));
      if (static_cast<std::uint32_t>(outcome) > 66) {
        ++failures;
      }
    }
  };
  const auto reader = [&]() {
    for (int step = 0; step < 200; ++step) {
      const std::vector<GroupSummary> groups = harness.governor->list_groups();
      if (groups.size() != 8) {
        ++failures;
      }
      for (const GroupSummary& summary : groups) {
        const std::optional<GroupSnapshot> snapshot = harness.governor->snapshot(summary.id);
        if (!snapshot.has_value()) {
          ++failures;
          continue;
        }
        if (snapshot->assignment.owners.size() != snapshot->bucket_count.value()) {
          ++failures;
        }
      }
    }
  };
  std::vector<std::thread> threads;
  for (std::uint32_t group = 0; group < 4; ++group) {
    threads.emplace_back(mutator, group);
  }
  threads.emplace_back(reader);
  threads.emplace_back(reader);
  for (std::thread& thread : threads) {
    thread.join();
  }
  ECMP_CHECK_EQ(failures.load(), 0);
  std::vector<Condition> problems;
  ECMP_CHECK(harness.governor->check_invariants(problems));
}
