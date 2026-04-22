OP_GET = 0
OP_PUT = 1
OP_DEL = 2
OP_ERROR = 3

NB_PORT = 5300

# Maximum byte lengths for wire-protocol name and value fields.
NB_NAME_LEN = 50
NB_VAL_LEN = 500

# Maximum names a single IPv4 / IPv6 interface address may register.
V4_NAME_LIMIT = 20
V6_NAME_LIMIT = 5

# IPv6 global-prefix subnet quotas.
V6_GLOB_LIMIT = 3
V6_SUBNET_LIMIT = 15000
V6_IFACE_LIMIT = 20

# Name expiry: 7 days without a refresh triggers deletion.
V6_ADDR_EXPIRY = 604800
MIN_NAME_DURATION = 604800
# Minimum penalty so very low usage still imposes some backpressure.
MIN_DURATION_PENALTY = 60

DO_BUMP = 1
DONT_BUMP = 0
THROW_BUMP = 2
