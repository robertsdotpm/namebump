OP_GET = 0
OP_PUT = 1
OP_DEL = 2
OP_ERROR = 3

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
V4_NAME_LIMIT = 20000
V6_NAME_LIMIT = 5000

# IPv6 global-prefix subnet quotas.
V6_GLOB_LIMIT = 3
V6_SUBNET_LIMIT = 15000
V6_IFACE_LIMIT = 2000

# Name expiry: 7 days without a refresh triggers deletion.
WEEK_SECS = 604800
V6_ADDR_EXPIRY = WEEK_SECS
MIN_NAME_DURATION = WEEK_SECS
# Minimum penalty so very low usage still imposes some backpressure.
MIN_DURATION_PENALTY = 60

DO_BUMP = 1
DONT_BUMP = 0
THROW_BUMP = 2
