#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "ecmp/identity.hpp"
#include "ecmp/lifecycle.hpp"

namespace ecmp {

// Explicit authority scope.  The default value denies everything: a caller that
// presents no scope is never granted wildcard authority.
enum class ScopeKind : std::uint32_t {
  DENY_ALL = 0,
  GROUP = 1,
  DESTINATION = 2,
  ROUTING_NAMESPACE = 3,
  FABRIC = 4,
};

[[nodiscard]] std::string_view to_string(ScopeKind kind) noexcept;

struct GroupKey;

struct AuthorityScope {
  ScopeKind kind = ScopeKind::DENY_ALL;
  FabricId fabric;
  RoutingNamespaceId routing_namespace;
  DestinationId destination;
  ECMPGroupId group;

  [[nodiscard]] static AuthorityScope deny_all() noexcept { return AuthorityScope{}; }
  [[nodiscard]] static AuthorityScope for_group(ECMPGroupId id) noexcept;
  [[nodiscard]] static AuthorityScope for_destination(DestinationId id,
                                                      RoutingNamespaceId routing_namespace,
                                                      FabricId fabric) noexcept;
  [[nodiscard]] static AuthorityScope for_routing_namespace(RoutingNamespaceId id,
                                                            FabricId fabric) noexcept;
  [[nodiscard]] static AuthorityScope for_fabric(FabricId id) noexcept;

  // True when this scope grants authority over the exact group identified by
  // (`key`, `group`).
  [[nodiscard]] bool covers(const GroupKey& key, const ECMPGroupId& group_id) const noexcept;

  [[nodiscard]] std::string render() const;

  friend bool operator==(const AuthorityScope&, const AuthorityScope&) = default;
};

enum class Capability : std::uint32_t {
  NONE = 0,
  MUTATE_GROUP = 1u << 0,
  PUBLISH_UPSTREAM = 1u << 1,
  ADMIN = 1u << 2,
};

[[nodiscard]] std::string_view to_string(Capability capability) noexcept;
[[nodiscard]] bool has_capability(std::uint32_t set, Capability capability) noexcept;

struct PublisherRegistration {
  PublisherId publisher;
  WorkerBootId worker_boot;
  AuthorityScope scope;
  std::uint32_t capabilities = 0;
  ProvenanceId provenance;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !publisher.is_nil() && !worker_boot.is_nil();
  }
};

// Everything a mutation must bind.  Connected is not authorized; a known
// publisher is not authorized; durable state is not live authority.
struct AuthorityContext {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  AuthorityScope scope;
  MutationAttemptId attempt;
  std::optional<MembershipGeneration> expected_membership;
  std::optional<AssignmentGeneration> expected_assignment;
  std::optional<AuthorityGeneration> expected_authority;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !publisher.is_nil() && !worker_boot.is_nil() && !attempt.is_nil();
  }
};

}  // namespace ecmp
