#pragma once

// ECMP Governor 1.0.0 - deterministic equal-cost multipath membership,
// eligibility and rebalance governance runtime.
//
// This umbrella header pulls in the complete public control-plane API.  The
// networked runtime (coordinator server, client, transport and local process
// supervision) lives in <ecmp/net.hpp>, <ecmp/server.hpp>, <ecmp/client.hpp> and
// <ecmp/process.hpp>.

#include "ecmp/assignment.hpp"
#include "ecmp/authority.hpp"
#include "ecmp/bytes.hpp"
#include "ecmp/cost.hpp"
#include "ecmp/digest.hpp"
#include "ecmp/governor.hpp"
#include "ecmp/group.hpp"
#include "ecmp/identity.hpp"
#include "ecmp/lifecycle.hpp"
#include "ecmp/limits.hpp"
#include "ecmp/outcome.hpp"
#include "ecmp/persistence.hpp"
#include "ecmp/protocol.hpp"
#include "ecmp/synthetic.hpp"
#include "ecmp/upstream.hpp"
#include "ecmp/version.hpp"
