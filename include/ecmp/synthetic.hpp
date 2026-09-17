#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ecmp/assignment.hpp"
#include "ecmp/cost.hpp"
#include "ecmp/governor.hpp"
#include "ecmp/group.hpp"
#include "ecmp/identity.hpp"

namespace ecmp {

// Deterministic SYNTHETIC fixtures.
//
// ECMP Governor 1.0.0 has no access to a physical leaf-spine fabric, no switch
// ASIC SDK and no traffic source.  Everything built through this header is
// synthetic: path identities, cost claims and group keys are derived from a seed
// so that examples, benchmarks and proofs are reproducible byte for byte.  These
// fixtures never stand in for measured traffic balancing, physical ECMP
// programming or real fabric topology.
struct SyntheticIds {
  FabricId fabric;
  RoutingNamespaceId routing_namespace;
  DestinationId destination;
  CostClassId cost_class;
  CostModelId cost_model;
  RouteClassId route_class;
  HashDomainId hash_domain;
  ProvenanceId provenance;
};

[[nodiscard]] SyntheticIds synthetic_ids(std::uint64_t seed);
[[nodiscard]] ECMPGroupId synthetic_group_id(std::uint64_t seed);
[[nodiscard]] ECMPMemberId synthetic_member_id(std::uint64_t seed);
[[nodiscard]] PathId synthetic_path_id(std::uint64_t seed);
[[nodiscard]] PublisherId synthetic_publisher_id(std::uint64_t seed);
[[nodiscard]] WorkerBootId synthetic_boot_id(std::uint64_t seed);
[[nodiscard]] MutationAttemptId synthetic_attempt_id(std::uint64_t seed);
[[nodiscard]] MultipathSetId synthetic_multipath_set_id(std::uint64_t seed);

[[nodiscard]] GroupKey synthetic_group_key(const SyntheticIds& ids);
[[nodiscard]] CostSemantics synthetic_cost_semantics(const SyntheticIds& ids,
                                                     std::uint64_t policy_generation = 1);
[[nodiscard]] CostClaim synthetic_cost_claim(const SyntheticIds& ids, std::uint64_t seed,
                                             std::int64_t units = 10,
                                             std::uint64_t policy_generation = 1);
[[nodiscard]] MemberSpec synthetic_member_spec(const SyntheticIds& ids, std::uint64_t member_seed,
                                               std::uint64_t path_seed,
                                               PathAuthorityGeneration path_authority,
                                               std::int64_t units = 10,
                                               std::uint64_t policy_generation = 1,
                                               bool administratively_enabled = true);
[[nodiscard]] std::vector<MemberSpec> synthetic_members(const SyntheticIds& ids,
                                                       std::uint32_t count,
                                                       PathAuthorityGeneration path_authority,
                                                       std::uint64_t path_seed_base = 1000,
                                                       std::uint64_t member_seed_base = 2000,
                                                       std::int64_t units = 10);
[[nodiscard]] AuthorityContext synthetic_authority(CoordinatorEpoch epoch,
                                                   const PublisherId& publisher,
                                                   const WorkerBootId& worker_boot,
                                                   const AuthorityScope& scope,
                                                   std::uint64_t attempt_seed);

}  // namespace ecmp
