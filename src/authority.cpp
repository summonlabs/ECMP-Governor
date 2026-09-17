#include "ecmp/authority.hpp"

#include <string>

#include "ecmp/group.hpp"
#include "ecmp/upstream.hpp"

namespace ecmp {

std::string_view to_string(ScopeKind kind) noexcept {
  switch (kind) {
    case ScopeKind::DENY_ALL: return "DENY_ALL";
    case ScopeKind::GROUP: return "GROUP";
    case ScopeKind::DESTINATION: return "DESTINATION";
    case ScopeKind::ROUTING_NAMESPACE: return "ROUTING_NAMESPACE";
    case ScopeKind::FABRIC: return "FABRIC";
  }
  return "UNKNOWN_SCOPE_KIND";
}

AuthorityScope AuthorityScope::for_group(ECMPGroupId id) noexcept {
  AuthorityScope scope;
  scope.kind = ScopeKind::GROUP;
  scope.group = id;
  return scope;
}

AuthorityScope AuthorityScope::for_destination(DestinationId id, RoutingNamespaceId routing_namespace,
                                               FabricId fabric) noexcept {
  AuthorityScope scope;
  scope.kind = ScopeKind::DESTINATION;
  scope.destination = id;
  scope.routing_namespace = routing_namespace;
  scope.fabric = fabric;
  return scope;
}

AuthorityScope AuthorityScope::for_routing_namespace(RoutingNamespaceId id, FabricId fabric) noexcept {
  AuthorityScope scope;
  scope.kind = ScopeKind::ROUTING_NAMESPACE;
  scope.routing_namespace = id;
  scope.fabric = fabric;
  return scope;
}

AuthorityScope AuthorityScope::for_fabric(FabricId id) noexcept {
  AuthorityScope scope;
  scope.kind = ScopeKind::FABRIC;
  scope.fabric = id;
  return scope;
}

bool AuthorityScope::covers(const GroupKey& key, const ECMPGroupId& group_id) const noexcept {
  switch (kind) {
    case ScopeKind::DENY_ALL:
      return false;
    case ScopeKind::GROUP:
      return !group.is_nil() && group == group_id;
    case ScopeKind::DESTINATION:
      return !destination.is_nil() && key.destination == destination &&
             (routing_namespace.is_nil() || key.routing_namespace == routing_namespace) &&
             (fabric.is_nil() || key.fabric == fabric);
    case ScopeKind::ROUTING_NAMESPACE:
      return !routing_namespace.is_nil() && key.routing_namespace == routing_namespace &&
             (fabric.is_nil() || key.fabric == fabric);
    case ScopeKind::FABRIC:
      return !fabric.is_nil() && key.fabric == fabric;
  }
  return false;
}

std::string AuthorityScope::render() const {
  std::string out(to_string(kind));
  switch (kind) {
    case ScopeKind::DENY_ALL:
      break;
    case ScopeKind::GROUP:
      out += " group=" + group.to_text();
      break;
    case ScopeKind::DESTINATION:
      out += " fabric=" + fabric.to_text();
      out += " namespace=" + routing_namespace.to_text();
      out += " destination=" + destination.to_text();
      break;
    case ScopeKind::ROUTING_NAMESPACE:
      out += " fabric=" + fabric.to_text();
      out += " namespace=" + routing_namespace.to_text();
      break;
    case ScopeKind::FABRIC:
      out += " fabric=" + fabric.to_text();
      break;
  }
  return out;
}

std::string_view to_string(Capability capability) noexcept {
  switch (capability) {
    case Capability::NONE: return "NONE";
    case Capability::MUTATE_GROUP: return "MUTATE_GROUP";
    case Capability::PUBLISH_UPSTREAM: return "PUBLISH_UPSTREAM";
    case Capability::ADMIN: return "ADMIN";
  }
  return "UNKNOWN_CAPABILITY";
}

bool has_capability(std::uint32_t set, Capability capability) noexcept {
  return (set & static_cast<std::uint32_t>(capability)) != 0;
}

std::optional<PathAuthorityObservation> UnknownPathAuthorityView::observe(const PathId&) const {
  return std::nullopt;
}

std::optional<MultipathSetGeneration> UnknownMultipathSetView::generation(
    const MultipathSetId&) const {
  return std::nullopt;
}

bool UnknownMultipathSetView::contains(const MultipathSetId&, MultipathSetGeneration,
                                       const PathId&) const {
  return false;
}

}  // namespace ecmp
