#include "ecmp/synthetic.hpp"

#include "ecmp/digest.hpp"

namespace ecmp {

SyntheticIds synthetic_ids(std::uint64_t seed) {
  SyntheticIds ids;
  ids.fabric = derive_id<FabricId>("ecmp.synthetic.fabric", seed);
  ids.routing_namespace = derive_id<RoutingNamespaceId>("ecmp.synthetic.namespace", seed);
  ids.destination = derive_id<DestinationId>("ecmp.synthetic.destination", seed);
  ids.cost_class = derive_id<CostClassId>("ecmp.synthetic.cost-class", seed);
  ids.cost_model = derive_id<CostModelId>("ecmp.synthetic.cost-model", seed);
  ids.route_class = derive_id<RouteClassId>("ecmp.synthetic.route-class", seed);
  ids.hash_domain = derive_id<HashDomainId>("ecmp.synthetic.hash-domain", seed);
  ids.provenance = derive_id<ProvenanceId>("ecmp.synthetic.provenance", seed);
  return ids;
}

ECMPGroupId synthetic_group_id(std::uint64_t seed) {
  return derive_id<ECMPGroupId>("ecmp.synthetic.group", seed);
}

ECMPMemberId synthetic_member_id(std::uint64_t seed) {
  return derive_id<ECMPMemberId>("ecmp.synthetic.member", seed);
}

PathId synthetic_path_id(std::uint64_t seed) {
  return derive_id<PathId>("ecmp.synthetic.path", seed);
}

PublisherId synthetic_publisher_id(std::uint64_t seed) {
  return derive_id<PublisherId>("ecmp.synthetic.publisher", seed);
}

WorkerBootId synthetic_boot_id(std::uint64_t seed) {
  return derive_id<WorkerBootId>("ecmp.synthetic.boot", seed);
}

MutationAttemptId synthetic_attempt_id(std::uint64_t seed) {
  return derive_id<MutationAttemptId>("ecmp.synthetic.attempt", seed);
}

MultipathSetId synthetic_multipath_set_id(std::uint64_t seed) {
  return derive_id<MultipathSetId>("ecmp.synthetic.multipath-set", seed);
}

GroupKey synthetic_group_key(const SyntheticIds& ids) {
  GroupKey key;
  key.fabric = ids.fabric;
  key.routing_namespace = ids.routing_namespace;
  key.destination = ids.destination;
  key.cost_class = ids.cost_class;
  return key;
}

CostSemantics synthetic_cost_semantics(const SyntheticIds& ids, std::uint64_t policy_generation) {
  CostSemantics semantics;
  semantics.cost_class = ids.cost_class;
  semantics.binding.model = ids.cost_model;
  semantics.binding.model_version = 1;
  semantics.binding.route_class = ids.route_class;
  semantics.binding.policy_generation = CostPolicyGeneration::from_value(policy_generation);
  return semantics;
}

CostClaim synthetic_cost_claim(const SyntheticIds& ids, std::uint64_t seed, std::int64_t units,
                               std::uint64_t policy_generation) {
  CostClaim claim;
  claim.cost_class = ids.cost_class;
  claim.binding.model = ids.cost_model;
  claim.binding.model_version = 1;
  claim.binding.route_class = ids.route_class;
  claim.binding.policy_generation = CostPolicyGeneration::from_value(policy_generation);
  claim.cost.units = units;
  claim.cost.scale = 0;
  claim.source = derive_id<ProvenanceId>("ecmp.synthetic.cost-source", seed);
  return claim;
}

MemberSpec synthetic_member_spec(const SyntheticIds& ids, std::uint64_t member_seed,
                                 std::uint64_t path_seed, PathAuthorityGeneration path_authority,
                                 std::int64_t units, std::uint64_t policy_generation,
                                 bool administratively_enabled) {
  MemberSpec spec;
  spec.member = synthetic_member_id(member_seed);
  spec.path = synthetic_path_id(path_seed);
  spec.path_authority = path_authority;
  spec.member_generation = MemberGeneration::from_value(1);
  spec.cost = synthetic_cost_claim(ids, member_seed, units, policy_generation);
  spec.provenance = derive_id<ProvenanceId>("ecmp.synthetic.member-source", member_seed);
  spec.administratively_enabled = administratively_enabled;
  return spec;
}

std::vector<MemberSpec> synthetic_members(const SyntheticIds& ids, std::uint32_t count,
                                          PathAuthorityGeneration path_authority,
                                          std::uint64_t path_seed_base,
                                          std::uint64_t member_seed_base, std::int64_t units) {
  std::vector<MemberSpec> members;
  members.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    members.push_back(synthetic_member_spec(ids, member_seed_base + index, path_seed_base + index,
                                            path_authority, units));
  }
  return members;
}

AuthorityContext synthetic_authority(CoordinatorEpoch epoch, const PublisherId& publisher,
                                     const WorkerBootId& worker_boot, const AuthorityScope& scope,
                                     std::uint64_t attempt_seed) {
  AuthorityContext authority;
  authority.epoch = epoch;
  authority.publisher = publisher;
  authority.worker_boot = worker_boot;
  authority.scope = scope;
  authority.attempt = synthetic_attempt_id(attempt_seed);
  return authority;
}

}  // namespace ecmp
