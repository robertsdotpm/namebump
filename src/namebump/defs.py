OP_GET = 0
OP_PUT = 1
OP_DEL = 2
OP_ERROR = 3
# Signed-owner-only query for the per-IP name quota state (used + cap)
# of the AF the request came in over.  Server reply puts a JSON-
# encoded {names_used, name_limit, af} blob in the packet's value
# field.  No name field is consulted; the response is keyed entirely
# by the requesting client_ip's quota row.
OP_USAGE = 4

NB_PORT = 5300

# Maximum byte lengths for wire-protocol name and value fields.
NB_NAME_LEN = 50
# 1024 (was 500): node addr_bytes optionally embeds MQTT broker
# and TURN server hint sections (the 6-part wire format), pushing
# typical addrs from ~280B to ~430-580B. The previous 500 cap
# silently truncated on PUT and parse_node_addr returned None on
# GET, breaking every nickname-resolved addr end-to-end. 1024
# gives room for the hint sections plus future protocol fields
# without forcing another wire-compat bump.
NB_VAL_LEN = 1024

# Maximum names a single IPv4 / IPv6 interface address may register.
V4_NAME_LIMIT = 20
V6_NAME_LIMIT = 5

# IPv6 global-prefix subnet quotas.
V6_SUBNET_LIMIT = 15000
V6_IFACE_LIMIT = 20

# Name expiry: 30 days without a refresh triggers deletion.
# Raised from 7 days because the previous lifetime combined with the
# quota-based penalty (now removed) made records appear to vanish
# unpredictably soon after registration -- users would register a
# nickname, see it pruned out hours or days later, and have no
# obvious cause.  30 days gives breathing room for occasional users
# while still GC-ing abandoned names eventually.
DAY_SECS = 86400
MONTH_SECS = 30 * DAY_SECS
V6_ADDR_EXPIRY = MONTH_SECS
MIN_NAME_DURATION = MONTH_SECS

DO_BUMP = 1
DONT_BUMP = 0
THROW_BUMP = 2

# Per-request TTL window (seconds). The packet carries its own ttl in the
# signed payload; the server rejects requests where now - updated > ttl.
# DEFAULT_REQUEST_TTL is what client packets request when none is supplied.
# MAX_REQUEST_TTL caps what the server will honour, so a leaked signed
# packet can't be replayed indefinitely just because its ttl was huge.
DEFAULT_REQUEST_TTL = 10
MAX_REQUEST_TTL = 60

# Tolerance for client/server clock skew when checking pkt.updated.
CLOCK_SKEW_SLACK = 5
