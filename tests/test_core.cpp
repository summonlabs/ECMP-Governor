#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <map>
#include <random>
#include <span>
#include <set>
#include <string>
#include <vector>

#include "ecmp/ecmp.hpp"
#include "test_framework.hpp"

namespace {

using namespace ecmp;

// ---------------------------------------------------------------------------
// Independent rebalance oracle.
//
// Three genuinely different methods must agree:
//   * the closed form  churn = bucket_count - sum(min(previous_share, target_share))
//   * a maximum-flow computation over "which buckets can keep their owner"
//   * exhaustive enumeration for tiny instances
// and the production rebalance must equal the lexicographically smallest
// minimum-churn assignment found by depth-first search in owner order.
// ---------------------------------------------------------------------------

int max_retained_flow(const std::vector<ECMPMemberId>& previous_owners,
                      const std::vector<ECMPMemberId>& members,
                      const std::vector<std::uint32_t>& target) {
  const int bucket_count = static_cast<int>(previous_owners.size());
  const int member_count = static_cast<int>(members.size());
  const int source = 0;
  const int bucket_base = 1;
  const int member_base = bucket_base + bucket_count;
  const int sink = member_base + member_count;
  const int node_count = sink + 1;

  std::vector<std::vector<int>> capacity(static_cast<std::size_t>(node_count),
                                         std::vector<int>(static_cast<std::size_t>(node_count), 0));
  for (int bucket = 0; bucket < bucket_count; ++bucket) {
    capacity[static_cast<std::size_t>(source)][static_cast<std::size_t>(bucket_base + bucket)] = 1;
    const ECMPMemberId owner = previous_owners[static_cast<std::size_t>(bucket)];
    if (owner.is_nil()) {
      continue;
    }
    for (int member = 0; member < member_count; ++member) {
      if (members[static_cast<std::size_t>(member)] == owner) {
        capacity[static_cast<std::size_t>(bucket_base + bucket)]
                [static_cast<std::size_t>(member_base + member)] = 1;
        break;
      }
    }
  }
  for (int member = 0; member < member_count; ++member) {
    capacity[static_cast<std::size_t>(member_base + member)][static_cast<std::size_t>(sink)] =
        static_cast<int>(target[static_cast<std::size_t>(member)]);
  }

  int flow = 0;
  for (;;) {
    std::vector<int> parent(static_cast<std::size_t>(node_count), -1);
    std::vector<int> queue;
    queue.push_back(source);
    parent[static_cast<std::size_t>(source)] = source;
    for (std::size_t head = 0; head < queue.size() && parent[static_cast<std::size_t>(sink)] < 0;
         ++head) {
      const int node = queue[head];
      for (int next = 0; next < node_count; ++next) {
        if (capacity[static_cast<std::size_t>(node)][static_cast<std::size_t>(next)] > 0 &&
            parent[static_cast<std::size_t>(next)] < 0) {
          parent[static_cast<std::size_t>(next)] = node;
          queue.push_back(next);
        }
      }
    }
    if (parent[static_cast<std::size_t>(sink)] < 0) {
      break;
    }
    int node = sink;
    while (node != source) {
      const int previous = parent[static_cast<std::size_t>(node)];
      --capacity[static_cast<std::size_t>(previous)][static_cast<std::size_t>(node)];
      ++capacity[static_cast<std::size_t>(node)][static_cast<std::size_t>(previous)];
      node = previous;
    }
    ++flow;
  }
  return flow;
}

struct LexMinOracle {
  const std::vector<ECMPMemberId>* previous_owners = nullptr;
  const std::vector<ECMPMemberId>* members = nullptr;
  std::vector<std::uint32_t> target;
  std::uint64_t min_churn = 0;
  std::vector<int> assignment;
  std::vector<std::uint32_t> used;
  std::vector<int> best;
  bool found = false;

  [[nodiscard]] int previous_index(std::size_t bucket) const {
    const ECMPMemberId owner = (*previous_owners)[bucket];
    if (owner.is_nil()) {
      return -1;
    }
    for (std::size_t index = 0; index < members->size(); ++index) {
      if ((*members)[index] == owner) {
        return static_cast<int>(index);
      }
    }
    return -1;
  }

  [[nodiscard]] std::uint64_t lower_bound(std::size_t bucket) const {
    std::vector<std::uint32_t> remaining = target;
    for (std::size_t index = 0; index < used.size(); ++index) {
      remaining[index] -= used[index];
    }
    std::uint64_t retainable = 0;
    for (std::size_t index = bucket; index < previous_owners->size(); ++index) {
      const int owner = previous_index(index);
      if (owner >= 0 && remaining[static_cast<std::size_t>(owner)] > 0) {
        ++retainable;
        --remaining[static_cast<std::size_t>(owner)];
      }
    }
    return static_cast<std::uint64_t>(previous_owners->size() - bucket) - retainable;
  }

  bool search(std::size_t bucket, std::uint64_t moves) {
    if (bucket == previous_owners->size()) {
      best = assignment;
      found = true;
      return true;
    }
    if (moves + lower_bound(bucket) > min_churn) {
      return false;
    }
    for (std::size_t member = 0; member < members->size(); ++member) {
      if (used[member] >= target[member]) {
        continue;
      }
      const std::uint64_t extra = previous_index(bucket) == static_cast<int>(member) ? 0u : 1u;
      if (moves + extra > min_churn) {
        continue;
      }
      assignment[bucket] = static_cast<int>(member);
      ++used[member];
      if (search(bucket + 1, moves + extra)) {
        return true;
      }
      --used[member];
      assignment[bucket] = -1;
    }
    return false;
  }

  std::vector<int> solve() {
    target = balanced_bucket_counts(static_cast<std::uint32_t>(previous_owners->size()),
                                    static_cast<std::uint32_t>(members->size()));
    const int retained = max_retained_flow(*previous_owners, *members, target);
    min_churn = previous_owners->size() - static_cast<std::uint64_t>(retained);
    assignment.assign(previous_owners->size(), -1);
    used.assign(members->size(), 0);
    found = search(0, 0);
    return best;
  }
};

// Exhaustive enumeration for tiny instances, used to validate the oracle itself.
struct BruteForceOracle {
  const std::vector<ECMPMemberId>* previous_owners = nullptr;
  const std::vector<ECMPMemberId>* members = nullptr;
  std::vector<std::uint32_t> target;
  std::uint64_t best_churn = 0;
  std::vector<int> best;
  bool found = false;

  void recurse(std::size_t bucket, std::uint64_t moves, std::vector<int>& assignment,
               std::vector<std::uint32_t>& used) {
    if (bucket == previous_owners->size()) {
      if (!found || moves < best_churn) {
        found = true;
        best_churn = moves;
        best = assignment;
      }
      return;
    }
    for (std::size_t member = 0; member < members->size(); ++member) {
      if (used[member] >= target[member]) {
        continue;
      }
      const ECMPMemberId owner = (*previous_owners)[bucket];
      const bool keeps = !owner.is_nil() && owner == (*members)[member];
      assignment[bucket] = static_cast<int>(member);
      ++used[member];
      recurse(bucket + 1, moves + (keeps ? 0u : 1u), assignment, used);
      --used[member];
      assignment[bucket] = -1;
    }
  }

  void solve() {
    target = balanced_bucket_counts(static_cast<std::uint32_t>(previous_owners->size()),
                                    static_cast<std::uint32_t>(members->size()));
    std::vector<int> assignment(previous_owners->size(), -1);
    std::vector<std::uint32_t> used(members->size(), 0);
    recurse(0, 0, assignment, used);
  }
};

std::vector<ECMPMemberId> member_list(std::uint32_t count, std::uint64_t seed) {
  std::vector<ECMPMemberId> members;
  for (std::uint32_t index = 0; index < count; ++index) {
    members.push_back(synthetic_member_id((seed * 1000) + index));
  }
  std::sort(members.begin(), members.end());
  return members;
}

}  // namespace

// --- identities -------------------------------------------------------------

ECMP_TEST(test_identity_encoding) {
  const ECMPGroupId id = synthetic_group_id(7);
  const std::string text = id.to_text();
  ECMP_CHECK_EQ(text.size(), std::size_t{32});
  const auto parsed = ECMPGroupId::parse(text);
  ECMP_REQUIRE(parsed.has_value());
  ECMP_CHECK(*parsed == id);
  ECMP_CHECK(!id.is_nil());

  // Uppercase spelling parses to the same identity; rendering stays lowercase.
  std::string upper = text;
  for (char& character : upper) {
    character = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
  }
  const auto upper_parsed = ECMPGroupId::parse(upper);
  ECMP_REQUIRE(upper_parsed.has_value());
  ECMP_CHECK(*upper_parsed == id);
  ECMP_CHECK_EQ(upper_parsed->to_text(), text);

  ECMP_CHECK(!ECMPGroupId::parse("").has_value());
  ECMP_CHECK(!ECMPGroupId::parse("00").has_value());
  ECMP_CHECK(!ECMPGroupId::parse(text + "00").has_value());
  ECMP_CHECK(!ECMPGroupId::parse(text.substr(1)).has_value());
  ECMP_CHECK(!ECMPGroupId::parse("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").has_value());
  ECMP_CHECK(!ECMPGroupId::parse("0000000000000000000000000000000g").has_value());
  ECMP_CHECK(ECMPGroupId{}.is_nil());
  ECMP_CHECK(ECMPGroupId::from_u64(0, 0).is_nil());
  ECMP_CHECK(!ECMPGroupId::from_u64(0, 1).is_nil());

  // Deterministic ordering: byte-wise lexicographic over the big-endian words.
  ECMP_CHECK(ECMPGroupId::from_u64(0, 1) < ECMPGroupId::from_u64(1, 0));
}

ECMP_TEST(test_generation_checked_increment) {
  const MembershipGeneration zero;
  ECMP_CHECK(zero.is_zero());
  const auto one = zero.next();
  ECMP_REQUIRE(one.has_value());
  ECMP_CHECK_EQ(one->value(), std::uint64_t{1});
  const MembershipGeneration maximum = MembershipGeneration::from_value(MembershipGeneration::kMaximum);
  ECMP_CHECK(!maximum.next().has_value());
  const MembershipGeneration almost = MembershipGeneration::from_value(MembershipGeneration::kMaximum - 1);
  ECMP_REQUIRE(almost.next().has_value());
  ECMP_CHECK_EQ(almost.next()->value(), MembershipGeneration::kMaximum);

  ECMP_CHECK(!BucketCount::make(0).has_value());
  ECMP_CHECK(!BucketCount::make(kAbsoluteMaxBuckets + 1).has_value());
  ECMP_REQUIRE(BucketCount::make(64).has_value());
  ECMP_CHECK_EQ(BucketCount::make(64)->value(), std::uint32_t{64});
}

// --- bounds and codecs ------------------------------------------------------

ECMP_TEST(test_encoder_decoder_bounds) {
  Encoder encoder(8);
  encoder.u8(1);
  encoder.u16(0x0203);
  encoder.u32(0x04050607u);
  encoder.u64(0x08090A0B0C0D0E0Full);
  encoder.boolean(true);
  encoder.text("abc");
  ECMP_CHECK(encoder.ok());
  const std::vector<std::uint8_t> bytes = encoder.bytes();

  Decoder decoder(bytes, 8);
  std::uint8_t u8 = 0;
  std::uint16_t u16 = 0;
  std::uint32_t u32 = 0;
  std::uint64_t u64 = 0;
  bool flag = false;
  std::string text;
  ECMP_CHECK(decoder.u8(u8));
  ECMP_CHECK(decoder.u16(u16));
  ECMP_CHECK(decoder.u32(u32));
  ECMP_CHECK(decoder.u64(u64));
  ECMP_CHECK(decoder.boolean(flag));
  ECMP_CHECK(decoder.text(text, 16));
  ECMP_CHECK(decoder.at_end());
  ECMP_CHECK_EQ(u8, std::uint8_t{1});
  ECMP_CHECK_EQ(u16, std::uint16_t{0x0203});
  ECMP_CHECK_EQ(u32, 0x04050607u);
  ECMP_CHECK_EQ(u64, 0x08090A0B0C0D0E0Full);
  ECMP_CHECK(flag);
  ECMP_CHECK_EQ(text, std::string("abc"));

  // A blob larger than the encoder bound is refused rather than truncated.
  Encoder bounded(4);
  bounded.text("abcdefgh");
  ECMP_CHECK(!bounded.ok());

  // Strict boolean decoding.
  const std::vector<std::uint8_t> bad_boolean{2};
  Decoder strict(bad_boolean, 8);
  bool value = false;
  ECMP_CHECK(!strict.boolean(value));
  ECMP_CHECK(strict.failed());
  // The decoder latches failure.
  std::uint8_t ignored = 0;
  ECMP_CHECK(!strict.u8(ignored));

  // Truncation is detected: a decoder over a one byte image cannot produce a
  // multi-byte value, and the failure latches.
  Decoder truncated(std::span<const std::uint8_t>(bytes.data(), 1), 8);
  ECMP_CHECK(truncated.u8(u8));
  ECMP_CHECK(!truncated.u64(u64));
  ECMP_CHECK(truncated.failed());
}

ECMP_TEST(test_sha256_known_vectors) {
  const auto hex = [](const Sha256::Value& value) {
    return Digest::from_bytes(value).to_text();
  };
  ECMP_CHECK_EQ(hex(Sha256::hash({})),
                std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  const std::string abc = "abc";
  ECMP_CHECK_EQ(
      hex(Sha256::hash(std::span<const std::uint8_t>(
          reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()))),
      std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  const std::string long_message =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  ECMP_CHECK_EQ(
      hex(Sha256::hash(std::span<const std::uint8_t>(
          reinterpret_cast<const std::uint8_t*>(long_message.data()), long_message.size()))),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  const std::string million(1000000, 'a');
  ECMP_CHECK_EQ(
      hex(Sha256::hash(std::span<const std::uint8_t>(
          reinterpret_cast<const std::uint8_t*>(million.data()), million.size()))),
      std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

  // Domain separation: the same payload under two domains must differ.
  const std::vector<std::uint8_t> payload{1, 2, 3};
  ECMP_CHECK(!(domain_digest("a", payload) == domain_digest("b", payload)));
  ECMP_CHECK(domain_digest("a", payload) == domain_digest("a", payload));
  ECMP_CHECK(!ECMPGroupId::from_u64(1, 2).is_nil());
}

// --- cost semantics ---------------------------------------------------------

ECMP_TEST(test_cost_representation_and_equality) {
  PathCost cost;
  cost.units = 12345;
  cost.scale = 0;
  ECMP_CHECK_EQ(cost.to_text(), std::string("12345"));
  cost.scale = 3;
  ECMP_CHECK_EQ(cost.to_text(), std::string("12.345"));
  cost.units = -5;
  cost.scale = 2;
  ECMP_CHECK_EQ(cost.to_text(), std::string("-0.05"));
  cost.units = -9223372036854775807LL - 1;
  cost.scale = 0;
  ECMP_CHECK_EQ(cost.to_text(), std::string("-9223372036854775808"));
  ECMP_CHECK((!PathCost{0, PathCost::kMaxScale + 1}.is_well_formed()));

  const SyntheticIds ids = synthetic_ids(3);
  const CostSemantics semantics = synthetic_cost_semantics(ids, 5);
  const CostClaim equal = synthetic_cost_claim(ids, 11, 10, 5);
  ECMP_CHECK(compare_cost_claim(semantics, equal.cost, equal) == CostCompatibility::EQUAL);

  CostClaim different_value = equal;
  different_value.cost.units = 11;
  ECMP_CHECK(compare_cost_claim(semantics, equal.cost, different_value) ==
             CostCompatibility::VALUE_MISMATCH);

  CostClaim different_class = equal;
  different_class.cost_class = synthetic_ids(99).cost_class;
  ECMP_CHECK(compare_cost_claim(semantics, equal.cost, different_class) ==
             CostCompatibility::CLASS_MISMATCH);

  CostClaim different_model = equal;
  different_model.binding.model = synthetic_ids(98).cost_model;
  ECMP_CHECK(compare_cost_claim(semantics, equal.cost, different_model) ==
             CostCompatibility::MODEL_MISMATCH);

  CostClaim different_policy = equal;
  different_policy.binding.policy_generation = CostPolicyGeneration::from_value(6);
  ECMP_CHECK(compare_cost_claim(semantics, equal.cost, different_policy) ==
             CostCompatibility::POLICY_STALE);

  // Different scale, same numeric value: exact representation equality rejects it.
  CostClaim scaled = equal;
  scaled.cost.units = 100;
  scaled.cost.scale = 1;
  ECMP_CHECK(compare_cost_claim(semantics, equal.cost, scaled) ==
             CostCompatibility::VALUE_MISMATCH);
}

// --- assignment and rebalance ----------------------------------------------

ECMP_TEST(test_initial_assignment_small_oracles) {
  const std::vector<std::uint32_t> eight_two = balanced_bucket_counts(8, 2);
  ECMP_CHECK_EQ(eight_two, (std::vector<std::uint32_t>{4, 4}));
  const std::vector<std::uint32_t> eight_three = balanced_bucket_counts(8, 3);
  ECMP_CHECK_EQ(eight_three, (std::vector<std::uint32_t>{3, 3, 2}));
  const std::vector<std::uint32_t> sixteen_five = balanced_bucket_counts(16, 5);
  ECMP_CHECK_EQ(sixteen_five, (std::vector<std::uint32_t>{4, 3, 3, 3, 3}));
  const std::vector<std::uint32_t> sixtyfour_four = balanced_bucket_counts(64, 4);
  ECMP_CHECK_EQ(sixtyfour_four, (std::vector<std::uint32_t>{16, 16, 16, 16}));

  // Exact cardinality oracles for small N.
  {
    const std::vector<ECMPMemberId> members = member_list(2, 1);
    const auto bucket_count = BucketCount::make(8);
    ECMP_REQUIRE(bucket_count.has_value());
    const RebalanceComputation computation = compute_initial_assignment(members, *bucket_count);
    ECMP_CHECK_EQ(computation.churn(), std::uint64_t{8});
    ECMP_CHECK_EQ(computation.assignment.owned_bucket_count(members[0]), std::uint32_t{4});
    ECMP_CHECK_EQ(computation.assignment.owned_bucket_count(members[1]), std::uint32_t{4});
  }
  {
    const std::vector<ECMPMemberId> members = member_list(3, 2);
    const auto bucket_count = BucketCount::make(8);
    ECMP_REQUIRE(bucket_count.has_value());
    const RebalanceComputation computation = compute_initial_assignment(members, *bucket_count);
    ECMP_CHECK_EQ(computation.assignment.owned_bucket_count(members[0]), std::uint32_t{3});
    ECMP_CHECK_EQ(computation.assignment.owned_bucket_count(members[1]), std::uint32_t{3});
    ECMP_CHECK_EQ(computation.assignment.owned_bucket_count(members[2]), std::uint32_t{2});
    ECMP_CHECK(check_assignment(computation.assignment, members) == AssignmentDefect::NONE);
  }
  {
    const std::vector<ECMPMemberId> members = member_list(5, 3);
    const auto bucket_count = BucketCount::make(16);
    ECMP_REQUIRE(bucket_count.has_value());
    const RebalanceComputation computation = compute_initial_assignment(members, *bucket_count);
    ECMP_CHECK_EQ(computation.assignment.owned_bucket_count(members[0]), std::uint32_t{4});
    for (std::size_t index = 1; index < members.size(); ++index) {
      ECMP_CHECK_EQ(computation.assignment.owned_bucket_count(members[index]), std::uint32_t{3});
    }
    ECMP_CHECK(check_assignment(computation.assignment, members) == AssignmentDefect::NONE);
  }
}

ECMP_TEST(test_rebalance_minimality_and_lexicographic_tie_break) {
  std::mt19937_64 random(0x5EED1234ull);
  for (int iteration = 0; iteration < 400; ++iteration) {
    const std::uint32_t bucket_count = 1 + static_cast<std::uint32_t>(random() % 16);
    const std::uint32_t member_count = 1 + static_cast<std::uint32_t>(random() % 5);
    const std::uint32_t old_member_count = 1 + static_cast<std::uint32_t>(random() % 5);
    const std::vector<ECMPMemberId> members = member_list(member_count, 11 + iteration);
    const std::vector<ECMPMemberId> old_members = member_list(old_member_count, 900 + iteration);

    BucketAssignment previous;
    const auto count = BucketCount::make(bucket_count);
    ECMP_REQUIRE(count.has_value());
    previous.count = *count;
    previous.owners.assign(bucket_count, ECMPMemberId{});
    for (std::uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
      if (random() % 5 == 0) {
        continue;  // deliberately leave some buckets unowned
      }
      previous.owners[bucket] = old_members[random() % old_member_count];
    }

    const RebalanceComputation production = compute_rebalance(previous, members, *count);
    ECMP_CHECK(check_assignment(production.assignment, members) == AssignmentDefect::NONE || members.empty());

    LexMinOracle oracle;
    oracle.previous_owners = &previous.owners;
    oracle.members = &members;
    const std::vector<int> expected = oracle.solve();
    ECMP_REQUIRE(oracle.found);

    ECMP_CHECK_EQ(production.churn(), oracle.min_churn);
    ECMP_CHECK_EQ(production.churn(), minimum_possible_churn(previous, members));
    for (std::uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
      const ECMPMemberId produced = production.assignment.owners[bucket];
      const int expected_index = expected[bucket];
      if (expected_index < 0) {
        ECMP_CHECK(produced.is_nil());
      } else {
        ECMP_CHECK_EQ(produced, members[static_cast<std::size_t>(expected_index)]);
      }
    }
  }
}

ECMP_TEST(test_rebalance_oracle_validated_by_brute_force) {
  std::mt19937_64 random(0xC0FFEEull);
  for (int iteration = 0; iteration < 120; ++iteration) {
    const std::uint32_t bucket_count = 1 + static_cast<std::uint32_t>(random() % 6);
    const std::uint32_t member_count = 1 + static_cast<std::uint32_t>(random() % 3);
    const std::vector<ECMPMemberId> members = member_list(member_count, 31 + iteration);
    const std::vector<ECMPMemberId> old_members = member_list(1 + static_cast<std::uint32_t>(random() % 3),
                                                             700 + iteration);
    BucketAssignment previous;
    const auto count = BucketCount::make(bucket_count);
    ECMP_REQUIRE(count.has_value());
    previous.count = *count;
    previous.owners.assign(bucket_count, ECMPMemberId{});
    for (std::uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
      previous.owners[bucket] = old_members[random() % old_members.size()];
    }

    LexMinOracle flow_oracle;
    flow_oracle.previous_owners = &previous.owners;
    flow_oracle.members = &members;
    const std::vector<int> flow_best = flow_oracle.solve();

    BruteForceOracle brute;
    brute.previous_owners = &previous.owners;
    brute.members = &members;
    brute.solve();
    ECMP_REQUIRE(brute.found);
    ECMP_CHECK_EQ(flow_oracle.min_churn, brute.best_churn);
    for (std::size_t bucket = 0; bucket < previous.owners.size(); ++bucket) {
      ECMP_CHECK_EQ(flow_best[bucket], brute.best[bucket]);
    }

    const RebalanceComputation production = compute_rebalance(previous, members, *count);
    ECMP_CHECK_EQ(production.churn(), brute.best_churn);
    for (std::size_t bucket = 0; bucket < previous.owners.size(); ++bucket) {
      ECMP_CHECK_EQ(production.assignment.owners[bucket],
                    members[static_cast<std::size_t>(brute.best[bucket])]);
    }
  }
}

ECMP_TEST(test_rebalance_is_a_pure_function_of_its_inputs) {
  const auto count = BucketCount::make(12);
  ECMP_REQUIRE(count.has_value());
  const std::vector<ECMPMemberId> members = member_list(4, 5);
  BucketAssignment previous;
  previous.count = *count;
  previous.owners.assign(12, ECMPMemberId{});
  for (std::uint32_t bucket = 0; bucket < 12; ++bucket) {
    previous.owners[bucket] = members[bucket % 4];
  }
  const RebalanceComputation first = compute_rebalance(previous, members, *count);
  // Permuting the member list is a different canonical order and therefore a
  // different (still deterministic) input; the same input must always produce the
  // same output, byte for byte.
  for (int repetition = 0; repetition < 5; ++repetition) {
    const RebalanceComputation again = compute_rebalance(previous, members, *count);
    ECMP_CHECK(again.assignment.owners == first.assignment.owners);
    ECMP_CHECK(again.moves.size() == first.moves.size());
    ECMP_CHECK(again.churn() == first.churn());
    ECMP_CHECK(again.assignment.digest() == first.assignment.digest());
  }
  // The move list explains every changed bucket exactly once.
  std::set<std::uint32_t> moved;
  for (const BucketMove& move : first.moves) {
    ECMP_CHECK(moved.insert(move.bucket.value()).second);
    ECMP_CHECK(!(move.from == move.to));
  }
}

ECMP_TEST(test_assignment_defects_are_detected) {
  const std::vector<ECMPMemberId> members = member_list(2, 8);
  const auto count = BucketCount::make(4);
  ECMP_REQUIRE(count.has_value());
  BucketAssignment assignment;
  assignment.count = *count;
  assignment.owners = {members[0], members[0], members[1], members[1]};
  ECMP_CHECK(check_assignment(assignment, members) == AssignmentDefect::NONE);

  BucketAssignment unassigned = assignment;
  unassigned.owners[2] = ECMPMemberId{};
  ECMP_CHECK(check_assignment(unassigned, members) == AssignmentDefect::UNASSIGNED_BUCKET);

  BucketAssignment unknown = assignment;
  unknown.owners[2] = synthetic_member_id(4242);
  ECMP_CHECK(check_assignment(unknown, members) == AssignmentDefect::UNKNOWN_OWNER);

  BucketAssignment unbalanced = assignment;
  unbalanced.owners[1] = members[1];
  ECMP_CHECK(check_assignment(unbalanced, members) == AssignmentDefect::UNBALANCED);

  BucketAssignment wrong_size = assignment;
  wrong_size.owners.pop_back();
  ECMP_CHECK(check_assignment(wrong_size, members) == AssignmentDefect::COUNT_MISMATCH);

  const std::vector<ECMPMemberId> duplicated{members[0], members[0]};
  ECMP_CHECK(check_assignment(assignment, duplicated) ==
             AssignmentDefect::DUPLICATE_MEMBER_INPUT);

  // An empty member set is the only legal producer of unowned buckets.
  BucketAssignment empty;
  empty.count = *count;
  empty.owners.assign(4, ECMPMemberId{});
  ECMP_CHECK(check_assignment(empty, {}) == AssignmentDefect::NONE);
  ECMP_CHECK(check_assignment(empty, members) == AssignmentDefect::UNASSIGNED_BUCKET);
}

// --- lifecycle --------------------------------------------------------------

namespace {

// Independently written transition matrix: 10 states x 18 events.  This must
// match the production table exactly for every pair.
bool expected_group_transition(GroupLifecycle state, GroupEvent event) {
  const bool member_event = event == GroupEvent::ADD_MEMBER || event == GroupEvent::REMOVE_MEMBER ||
                            event == GroupEvent::DISABLE_MEMBER ||
                            event == GroupEvent::ENABLE_MEMBER;
  const bool invalidation = event == GroupEvent::INVALIDATE_PATH ||
                            event == GroupEvent::INVALIDATE_MULTIPATH ||
                            event == GroupEvent::INVALIDATE_COST ||
                            event == GroupEvent::INVALIDATE_EPOCH;
  const bool ordinary = member_event || invalidation || event == GroupEvent::REVALIDATE;
  switch (state) {
    case GroupLifecycle::DECLARED:
      return ordinary || event == GroupEvent::WITHDRAW || event == GroupEvent::REVOKE ||
             event == GroupEvent::SUPERSEDE || event == GroupEvent::RETIRE;
    case GroupLifecycle::ACTIVE:
    case GroupLifecycle::DEGRADED:
      return ordinary || event == GroupEvent::PLAN_REBALANCE ||
             event == GroupEvent::COMMIT_REBALANCE || event == GroupEvent::ABORT_REBALANCE ||
             event == GroupEvent::WITHDRAW || event == GroupEvent::REVOKE ||
             event == GroupEvent::SUPERSEDE || event == GroupEvent::RETIRE;
    case GroupLifecycle::REVALIDATION_REQUIRED:
      return ordinary || event == GroupEvent::WITHDRAW || event == GroupEvent::REVOKE ||
             event == GroupEvent::SUPERSEDE || event == GroupEvent::RETIRE;
    case GroupLifecycle::REBALANCING:
      return invalidation || event == GroupEvent::REVALIDATE ||
             event == GroupEvent::COMMIT_REBALANCE || event == GroupEvent::ABORT_REBALANCE ||
             event == GroupEvent::WITHDRAW || event == GroupEvent::REVOKE ||
             event == GroupEvent::SUPERSEDE || event == GroupEvent::RETIRE;
    case GroupLifecycle::WITHDRAWING:
      return event == GroupEvent::COMPLETE_WITHDRAW || event == GroupEvent::REVOKE ||
             event == GroupEvent::RETIRE;
    case GroupLifecycle::WITHDRAWN:
      return event == GroupEvent::REVOKE || event == GroupEvent::SUPERSEDE ||
             event == GroupEvent::RETIRE;
    case GroupLifecycle::REVOKED:
    case GroupLifecycle::SUPERSEDED:
      return event == GroupEvent::RETIRE;
    case GroupLifecycle::RETIRED:
      return false;
  }
  return false;
}

bool expected_member_transition(MemberState state, MemberEvent event) {
  switch (state) {
    case MemberState::ACTIVE:
      return event == MemberEvent::UPSTREAM_STALE || event == MemberEvent::COST_STALE ||
             event == MemberEvent::DISABLE || event == MemberEvent::WITHDRAW ||
             event == MemberEvent::RETIRE;
    case MemberState::REVALIDATION_REQUIRED:
      return event == MemberEvent::UPSTREAM_STALE || event == MemberEvent::COST_STALE ||
             event == MemberEvent::UPSTREAM_RESTORED || event == MemberEvent::DISABLE ||
             event == MemberEvent::WITHDRAW || event == MemberEvent::RETIRE;
    case MemberState::INELIGIBLE:
      return event == MemberEvent::ENABLE || event == MemberEvent::UPSTREAM_STALE ||
             event == MemberEvent::COST_STALE || event == MemberEvent::WITHDRAW ||
             event == MemberEvent::RETIRE;
    case MemberState::WITHDRAWN:
      return event == MemberEvent::DECLARE || event == MemberEvent::RETIRE;
    case MemberState::RETIRED:
      return false;
  }
  return false;
}

}  // namespace

ECMP_TEST(test_group_lifecycle_matrix_is_exhaustive) {
  for (std::uint32_t state_value = 1; state_value <= kGroupLifecycleCount; ++state_value) {
    const auto state = static_cast<GroupLifecycle>(state_value);
    for (std::uint32_t event_value = 1; event_value <= kGroupEventCount; ++event_value) {
      const auto event = static_cast<GroupEvent>(event_value);
      const bool allowed = lifecycle_allows(state, event);
      ECMP_CHECK_EQ(allowed, expected_group_transition(state, event));

      LifecycleInputs inputs;
      inputs.declared_members = 3;
      inputs.active_members = 2;
      inputs.min_active_members = 2;
      inputs.authority_current = true;
      const std::optional<GroupLifecycle> target = apply_group_event(state, event, inputs);
      ECMP_CHECK_EQ(target.has_value(), allowed);
      if (!target.has_value()) {
        continue;
      }
      switch (event) {
        case GroupEvent::CREATE:
          ECMP_CHECK(*target == GroupLifecycle::DECLARED);
          break;
        case GroupEvent::PLAN_REBALANCE:
          ECMP_CHECK(*target == GroupLifecycle::REBALANCING);
          break;
        case GroupEvent::WITHDRAW:
          ECMP_CHECK(*target == GroupLifecycle::WITHDRAWING);
          break;
        case GroupEvent::COMPLETE_WITHDRAW:
          ECMP_CHECK(*target == GroupLifecycle::WITHDRAWN);
          break;
        case GroupEvent::REVOKE:
          ECMP_CHECK(*target == GroupLifecycle::REVOKED);
          break;
        case GroupEvent::SUPERSEDE:
          ECMP_CHECK(*target == GroupLifecycle::SUPERSEDED);
          break;
        case GroupEvent::RETIRE:
          ECMP_CHECK(*target == GroupLifecycle::RETIRED);
          break;
        default:
          ECMP_CHECK(*target == GroupLifecycle::ACTIVE);
          break;
      }
    }
  }
}

ECMP_TEST(test_derived_lifecycle_boundaries) {
  LifecycleInputs inputs;
  inputs.declared_members = 0;
  ECMP_CHECK(derive_lifecycle(inputs) == GroupLifecycle::DECLARED);

  inputs.declared_members = 3;
  inputs.active_members = 0;
  ECMP_CHECK(derive_lifecycle(inputs) == GroupLifecycle::REVALIDATION_REQUIRED);

  inputs.active_members = 1;
  inputs.min_active_members = 2;
  ECMP_CHECK(derive_lifecycle(inputs) == GroupLifecycle::DEGRADED);

  inputs.active_members = 2;
  ECMP_CHECK(derive_lifecycle(inputs) == GroupLifecycle::ACTIVE);

  inputs.active_members = 3;
  ECMP_CHECK(derive_lifecycle(inputs) == GroupLifecycle::ACTIVE);

  inputs.authority_current = false;
  ECMP_CHECK(derive_lifecycle(inputs) == GroupLifecycle::REVALIDATION_REQUIRED);

  inputs.authority_current = true;
  inputs.plan_pending = true;
  ECMP_CHECK(derive_lifecycle(inputs) == GroupLifecycle::REBALANCING);
}

ECMP_TEST(test_member_lifecycle_matrix_is_exhaustive) {
  for (std::uint32_t state_value = 1; state_value <= kMemberStateCount; ++state_value) {
    const auto state = static_cast<MemberState>(state_value);
    for (std::uint32_t event_value = 1; event_value <= kMemberEventCount; ++event_value) {
      const auto event = static_cast<MemberEvent>(event_value);
      const bool allowed = member_lifecycle_allows(state, event);
      ECMP_CHECK_EQ(allowed, expected_member_transition(state, event));
      MemberInputs inputs;
      const std::optional<MemberState> target = apply_member_event(state, event, inputs);
      ECMP_CHECK_EQ(target.has_value(), allowed);
      if (target.has_value()) {
        ECMP_CHECK(*target == MemberState::ACTIVE);
      }
    }
  }

  // Every combination of member flags resolves to exactly one state.
  for (int mask = 0; mask < 16; ++mask) {
    MemberInputs inputs;
    inputs.retired = (mask & 8) != 0;
    inputs.declared = (mask & 4) != 0;
    inputs.upstream_current = (mask & 2) != 0;
    inputs.administratively_enabled = (mask & 1) != 0;
    const MemberState state = derive_member_state(inputs);
    if (inputs.retired) {
      ECMP_CHECK(state == MemberState::RETIRED);
    } else if (!inputs.declared) {
      ECMP_CHECK(state == MemberState::WITHDRAWN);
    } else if (!inputs.upstream_current) {
      ECMP_CHECK(state == MemberState::REVALIDATION_REQUIRED);
    } else if (!inputs.administratively_enabled) {
      ECMP_CHECK(state == MemberState::INELIGIBLE);
    } else {
      ECMP_CHECK(state == MemberState::ACTIVE);
    }
  }
}

ECMP_TEST(test_currentness_causes_are_distinct) {
  Currentness current;
  ECMP_CHECK(current.is_current());
  ECMP_CHECK_EQ(current.render(), std::string("CURRENT"));
  ECMP_CHECK(current.authority_current());

  Currentness stale_path;
  stale_path.add(CurrentnessCause::STALE_PATH_AUTHORITY);
  ECMP_CHECK(!stale_path.is_current());
  ECMP_CHECK(stale_path.authority_current());  // a stale path does not void group authority
  ECMP_CHECK_EQ(stale_path.render(), std::string("STALE_PATH_AUTHORITY"));

  Currentness stale_epoch;
  stale_epoch.add(CurrentnessCause::STALE_EPOCH);
  ECMP_CHECK(!stale_epoch.authority_current());

  Currentness fenced;
  fenced.add(CurrentnessCause::FENCED_PUBLISHER);
  ECMP_CHECK(!fenced.authority_current());

  Currentness both;
  both.add(CurrentnessCause::STALE_MULTIPATH_SET);
  both.add(CurrentnessCause::STALE_COST_CLASS);
  const std::vector<CurrentnessCause> causes = both.causes();
  ECMP_REQUIRE(causes.size() == 2);
  ECMP_CHECK(causes[0] == CurrentnessCause::STALE_MULTIPATH_SET);
  ECMP_CHECK(causes[1] == CurrentnessCause::STALE_COST_CLASS);
  ECMP_CHECK_EQ(both.render(), std::string("STALE_MULTIPATH_SET|STALE_COST_CLASS"));
}
