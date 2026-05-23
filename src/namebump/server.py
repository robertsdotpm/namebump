"""
This is a server that allows anyone to store key-value records.
    - Keys (or names) point to an ECDSA pub key (owner.)
    - Anyone who knows the key can read the value.
    - The owner can change the value with a signed request.
    - Only those with the private key can update the value.
    - There is a set number of names allocated per IP.
    - Since many people have dynamic IPs names must be
    periodically 'refreshed' which prevents expiry and ensures
    that they are associated with the right IP.
    - Names that expire are removed and unneeded IPs are deleted.
    - The alive duration for a name drops based on name usage per IP.
    - Thus, names are repeatedly migrated been IPs and refreshed
    as they are needed. Or allowed to expire automatically.

This is a registration-less, permissioned, key-value store
that uses IP limits to reduce spam.
"""

import os
import sys
import json
import signal
import asyncio
import aiomysql
from ecdsa import VerifyingKey, SECP256k1, SigningKey, BadSignatureError
from aionetiface import (
    Interface,
    SysClock,
    IPRange,
    TCP,
    UDP,
    IP4,
    IP6,
    DB_READ_LOCK,
    DB_WRITE_LOCK,
    log,
    log_exception,
    fstr,
    h_to_b,
    proto_send,
)
from aionetiface.net.daemon import Daemon
from aionetiface.utility.signing import ecdsa_verify_async
from aionetiface.vendor.ecies import encrypt, decrypt
from .packet import Packet
from .defs import (
    OP_GET,
    OP_PUT,
    OP_DEL,
    OP_USAGE,
    OP_ERROR,
    V4_NAME_LIMIT,
    V6_NAME_LIMIT,
    MIN_NAME_DURATION,
    V6_SUBNET_LIMIT,
    V6_IFACE_LIMIT,
    V6_ADDR_EXPIRY,
    NB_PORT,
    DONT_BUMP,
    MAX_REQUEST_TTL,
    CLOCK_SKEW_SLACK,
)


class ResourceLimit(Exception):
    """Raised when a per-IP name or address allocation limit is exceeded."""


async def v6_range_usage(
    cur, v6_glob_main, v6_glob_extra, v6_lan_id, _
):
    """Return the number of subnets and interfaces used within an IPv6 global prefix."""
    # Count number of subnets used.
    sql = (
        "SELECT COUNT(DISTINCT v6_lan_id) "
        "FROM ipv6s WHERE v6_glob_main=%s AND v6_glob_extra=%s FOR UPDATE"
    )
    await cur.execute(
        sql,
        (
            int(v6_glob_main),
            int(v6_glob_extra),
        ),
    )
    v6_subnets_used = (await cur.fetchone())[0]

    # Count number of interfaces used.
    sql = (
        "SELECT COUNT(id) FROM ipv6s "
        "WHERE v6_glob_main=%s AND v6_glob_extra=%s "
        "AND v6_lan_id=%s FOR UPDATE"
    )
    sql_params = (
        int(v6_glob_main),
        int(v6_glob_extra),
        int(v6_lan_id),
    )
    await cur.execute(sql, sql_params)
    v6_ifaces_used = (await cur.fetchone())[0]

    # Return results.
    return v6_subnets_used, v6_ifaces_used


async def v6_exists(
    cur, v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id
):
    """Check whether an IPv6 LAN segment and full interface record exist in the DB."""
    # Check if v6 subnet component exists.
    lan_sql = (
        "SELECT id FROM ipv6s WHERE v6_glob_main=%s "
        "AND v6_glob_extra=%s AND v6_lan_id=%s "
    )
    await cur.execute(
        lan_sql,
        (
            int(v6_glob_main),
            int(v6_glob_extra),
            int(v6_lan_id),
        ),
    )
    v6_lan_exists = (await cur.fetchone()) is not None

    # Check if IPv6 record exists.
    iface_sql = lan_sql + "AND v6_iface_id=%s"
    await cur.execute(
        iface_sql,
        (
            int(v6_glob_main),
            int(v6_glob_extra),
            int(v6_lan_id),
            int(v6_iface_id),
        ),
    )
    v6_record = await cur.fetchone()

    # Return results.
    return v6_lan_exists, v6_record


async def v6_insert(
    cur,
    v6_glob_main,
    v6_glob_extra,
    v6_lan_id,
    v6_iface_id,
    now,
):
    """Insert a new IPv6 address record and return its row ID."""
    # Insert a new IPv6 IP.
    sql = """INSERT INTO ipv6s
        (
            v6_glob_main,
            v6_glob_extra,
            v6_lan_id,
            v6_iface_id,
            timestamp
        )
        VALUES (%s, %s, %s, %s, %s)
    """
    sql_params = (
        int(v6_glob_main),
        int(v6_glob_extra),
        int(v6_lan_id),
        int(v6_iface_id),
        now,
    )
    await cur.execute(sql, sql_params)

    # Return the new row index.
    return cur.lastrowid


def get_v6_parts(ipr):
    """Break down an IPv6 address into (glob_main, glob_extra, lan_id, iface_id) for DB storage."""
    ip_str = str(ipr)  # Normalize IPv6.
    v6_glob_main = int(ip_str[:9].replace(":", ""), 16)  # :
    v6_glob_extra = int(ip_str[10:14], 16)
    v6_lan_id = int(ip_str[15:19], 16)
    v6_iface_id = int(ip_str[20:].replace(":", ""), 16)  # :
    v6_parts = (v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id)

    return v6_parts


async def record_v6(params, serv, now):
    """Record an IPv6 address, enforcing subnet and interface limits, and return its row ID."""
    # Replace ipr parameter with v6_parts.
    params = (params[0],) + get_v6_parts(params[1])

    # Get consumption numbers for the IPv6 range.
    v6_subnets_used, v6_ifaces_used = await v6_range_usage(*params)

    # Check whether the LAN ID already exists.
    # If the whole IPv6 already exists the record is not None.
    v6_lan_exists, v6_record = await v6_exists(*params)

    # Start logic to handle inserting the IPv6.
    if v6_record is None:
        # Are we within the subnet limitations?
        if not (v6_lan_exists or (v6_subnets_used < serv.v6_subnet_limit)):
            raise ResourceLimit("IPv6 subnet limit reached.")

        # Are we within the iface limitations?
        if not (v6_ifaces_used < serv.v6_iface_limit):
            raise ResourceLimit("IPv6 iface limit reached.")

        # IP row ID.
        ip_id = await v6_insert(*params, now)
    else:
        # IP row ID.
        ip_id = v6_record[0]

    return ip_id


async def record_v4(params, serv, now):
    """Record an IPv4 address if absent and return its row ID."""
    # Main params.
    cur, ipr = params

    # Check if IPv4 exists.
    sql = "SELECT id FROM ipv4s WHERE v4_val=%s FOR UPDATE"
    await cur.execute(sql, (int(ipr),))
    row = await cur.fetchone()
    if row is not None:
        # If it does return the ID.
        ip_id = row[0]
    else:
        # Otherwise insert the new IP and return its row ID.
        sql = "INSERT INTO ipv4s (v4_val, timestamp) VALUES (%s, %s)"
        await cur.execute(
            sql,
            (
                int(ipr),
                now,
            ),
        )
        ip_id = cur.lastrowid

    return ip_id


async def record_ip(af, params, serv, now):
    """Dispatch to the AF-specific IP recorder and return the resulting row ID."""
    if af == IP6:
        return await record_v6(params, serv, now)

    # Load existing ip_id or create it - V4.
    if af == IP4:
        return await record_v4(params, serv, now)

    raise ValueError("Unsupported address family: {}".format(af))


def name_limit_by_af(af, serv):
    """Return the per-IP name limit for the given address family."""
    if af == IP4:
        return serv.v4_name_limit
    if af == IP6:
        return serv.v6_name_limit
    raise ValueError("Unsupported address family: {}".format(af))


async def fetch_name(cur, name, lock=DB_WRITE_LOCK):
    """Fetch a name row from the DB, optionally locking it for write."""
    # Does name already exist.
    if lock == DB_WRITE_LOCK:
        sql = "SELECT * FROM names WHERE name=%s FOR UPDATE"
    else:
        sql = "SELECT * FROM names WHERE name=%s"

    await cur.execute(sql, (name,))
    row = await cur.fetchone()
    return row


async def get_names_used(cur, af, ip_id):
    """Return the count of names currently owned by a given IP row."""
    sql = "SELECT id FROM names WHERE af=%s AND ip_id=%s FOR UPDATE"
    await cur.execute(sql, (int(af), int(ip_id)))
    rows = await cur.fetchall()
    return len(rows)


async def record_name(
    cur,
    serv,
    af,
    ip_id,
    name,
    value,
    owner_pub,
    req_time,
):
    """Insert or update a name record, enforcing the per-IP name limit."""
    # Does name already exist.
    row = await fetch_name(cur, name)
    name_exists = row is not None

    # Get names used and limit.  Used below to decide whether a new
    # insert is permitted; previously also used to compute a
    # freshness penalty that subtracted from the record's lifetime,
    # but that produced surprising behaviour -- a user with 19/20
    # names had any new registration stored as nearly-expired and
    # could see it pruned almost immediately, with no externally
    # visible reason.  The cap is now a flat "new inserts above the
    # limit are rejected"; existing records get the full lifetime.
    names_used = await get_names_used(cur, af, ip_id)
    name_limit = name_limit_by_af(af, serv)

    # Store the unmodified request time as the freshness anchor.
    # Pruning condition is now-timestamp >= MIN_NAME_DURATION, so a
    # record stored with timestamp=req_time lasts exactly one full
    # MIN_NAME_DURATION before being eligible for deletion.
    expiry = req_time

    # Update an existing name.
    if name_exists:
        # The per-IP cap below only guards the INSERT path, but an
        # UPDATE can also reassign ip_id -- a name re-registered from
        # a different source IP.  Relocating a name onto an IP that is
        # already at the limit slips one past the cap: the destination
        # ends up with name_limit + 1 names (this is exactly how a
        # 21/20 quota state arises).  When the update actually moves
        # the name (its stored af / ip_id differ from the request's),
        # enforce the same limit against the destination.  names_used
        # was counted for the destination (af, ip_id) and does NOT
        # include this name yet -- it still lives on the old row -- so
        # a plain >= comparison is correct.  An in-place refresh (same
        # af and ip_id) skips the check: the name is already counted
        # there and must always be allowed to refresh its value.
        old_af = int(row[4])
        old_ip_id = int(row[5])
        relocating = (old_af, old_ip_id) != (int(af), int(ip_id))
        if relocating and names_used >= name_limit:
            raise ResourceLimit("insert name limit reached.")

        sql = """
        UPDATE names SET
        value=%s,
        af=%s,
        ip_id=%s,
        timestamp=%s,
        updated=%s
        WHERE name=%s
        """
        ret = await cur.execute(
            sql,
            (
                value,
                int(af),
                int(ip_id),
                expiry,
                req_time,
                name
            ),
        )
        if not ret:
            return None

        row = (row[0], name, value, row[3], af, ip_id, expiry, req_time)
        return row

    # Create a new name.
    # Ensure name limit is respected.
    # [ ... active names, ? ]
    if names_used >= name_limit:
        raise ResourceLimit("insert name limit reached.")

    # Insert a brand new name.
    sql = """
    INSERT INTO names
    (
        name,
        value,
        owner_pub,
        af,
        ip_id,
        timestamp,
        updated
    )
    VALUES(%s, %s, %s, %s, %s, %s, %s)
    """
    ret = await cur.execute(
        sql,
        (
            name,
            value,
            owner_pub,
            int(af),
            int(ip_id),
            expiry,
            req_time,
        ),
    )

    # Fetch the new row (so we know the ID.)
    return await fetch_name(cur, name)


async def verified_delete_name(db_con, cur, name):
    """Delete a name record from the DB if it exists, then commit."""
    row = await fetch_name(cur, name)
    if row is None:
        await db_con.rollback()  # Nothing to do
        return

    sql = "DELETE FROM names WHERE name = %s"
    await cur.execute(sql, (name,))
    await db_con.commit()  # Commit success


async def verified_pruning(db_con, cur, serv, updated):
    """Delete expired names and any IP rows that no longer have associated names."""
    # Delete all names that haven't been updated for X seconds.
    sql = """
    DELETE FROM names
    WHERE %s >= timestamp AND ((%s - timestamp) >= %s)
    """
    await cur.execute(
        sql,
        (
            updated,
            updated,
            int(serv.min_name_duration),
        ),
    )

    # Delete all IPs that don't have associated names.
    sql_ipv4 = """
        DELETE FROM ipv4s WHERE id NOT IN (
            SELECT ip_id as id
            FROM (
                SELECT ip_id
                FROM names
                WHERE af=%s
            ) AS results
        );
        """
    sql_ipv6 = """
        DELETE FROM ipv6s WHERE id NOT IN (
            SELECT ip_id as id
            FROM (
                SELECT ip_id
                FROM names
                WHERE af=%s
            ) AS results
        );
        """
    for sql, af in [[sql_ipv4, "2"], [sql_ipv6, "10"]]:
        await cur.execute(sql, (af,))


async def verified_write_name(
    db_con,
    cur,
    serv,
    behavior,
    name,
    value,
    owner_pub,
    af,
    ip_str,
    now,
    req_time,
):
    """Record or update a name-to-IP mapping, optionally pruning stale records first."""
    # Convert ip_str into an IPRange instance.
    host_limit = 0
    ipr = IPRange(ip_str, bitlen=host_limit)

    # Unneeded records get deleted.
    if behavior != DONT_BUMP:
        # If this fails, the whole transaction rolls back
        await verified_pruning(db_con, cur, serv, now)
        # Commit pruning before record_ip / record_name.  Without this,
        # a downstream ResourceLimit raise would roll back pruning along
        # with the failed put, leaving the orphan rows behind so the
        # next put attempt hits the same limits and fails the same way.
        # Committing pruning independently means a failed first put
        # still durably cleans up old state, so retries see the pruned
        # counts.
        await db_con.commit()

    # Record IP if needed and get its ID.
    # If it's V6 allocation limits are enforced on subnets.
    ip_id = await record_ip(
        af,
        (
            cur,
            ipr,
        ),
        serv,
        now,
    )
    await db_con.commit()

    # Record name if needed and get its ID.
    name_row = await record_name(cur, serv, af, ip_id, name, value, owner_pub, req_time)

    if name_row is None:
        raise ValueError("Name write failed — duplicate timestamp or conflict.")

    # If we got here, everything is valid.
    await db_con.commit()


class Server(Daemon):
    """TCP server that stores signed key-value records with per-IP allocation limits."""

    def __init__(
        self,
        db_user,
        db_pass,
        db_name,
        reply_sk,
        reply_pk,
        sys_clock,
        v4_name_limit=V4_NAME_LIMIT,
        v6_name_limit=V6_NAME_LIMIT,
        min_name_duration=MIN_NAME_DURATION,
        v6_addr_expiry=V6_ADDR_EXPIRY,
    ):
        self.db_user = db_user
        self.db_pass = db_pass
        self.db_name = db_name
        self.reply_sk = SigningKey.from_string(reply_sk, curve=SECP256k1)
        self.reply_pk = reply_pk
        self.sys_clock = sys_clock
        self.v4_name_limit = v4_name_limit
        self.v6_name_limit = v6_name_limit
        self.min_name_duration = min_name_duration
        self.v6_addr_expiry = v6_addr_expiry
        self.v6_subnet_limit = V6_SUBNET_LIMIT
        self.v6_iface_limit = V6_IFACE_LIMIT
        self.debug = False
        super().__init__()

    def serv_resp(self, pkt):
        """Serialise a response packet, optionally encrypting it with the requester's reply key."""
        reply_pk = pkt.reply_pk

        # Replace received packet reply address with our own.
        pkt.reply_pk = self.reply_pk

        # Serialize updated response.
        buf = pkt.get_msg_to_sign()

        # Send encrypted if supported.
        if reply_pk is not None:
            buf = encrypt(reply_pk, buf)

        return buf

    def set_debug(self, val):
        """Enable or disable verbose debug output."""
        self.debug = val

    def set_v6_limits(self, v6_subnet_limit, v6_iface_limit):
        """Set per-subnet and per-interface IPv6 registration limits."""
        self.v6_subnet_limit = v6_subnet_limit
        self.v6_iface_limit = v6_iface_limit

    async def handle_get(self, pipe, cur, pkt):
        """Look up a name in the database and send its current value back to the client."""
        row = await fetch_name(cur, pkt.name, DB_READ_LOCK)
        if row:
            resp = Packet(
                op=OP_GET,
                name=pkt.name,
                value=row[2],
                updated=row[6],
                vkc=row[3],
                pkid=pkt.pkid,
                reply_pk=pkt.reply_pk,
            )
        else:
            resp = Packet(
                op=OP_GET,
                name=pkt.name,
                value=b"",
                updated=0,
                vkc=pkt.vkc,
                pkid=pkt.pkid,
                reply_pk=pkt.reply_pk,
            )

        await proto_send(pipe, self.serv_resp(resp))

    async def handle_put(
        self, pipe, cur, db_con, pkt, client_tup
    ):
        """Validate the packet signature and write or update a name record in the database."""
        # Validate signature.  ECDSA verify (~2-10ms) runs on the
        # default thread pool executor so the event loop stays free
        # under concurrent load.
        if not pkt.vkc or not pkt.sig or not await pkt.is_valid_sig_async():
            raise PermissionError("PUT requires valid signature")

        # Ensure signature for update is correct.
        row = await fetch_name(cur, pkt.name, DB_READ_LOCK)
        if row:
            vk = VerifyingKey.from_string(row[3], curve=SECP256k1)
            # vk.verify raises BadSignatureError on mismatch; the
            # shared executor-offloaded helper propagates the
            # exception via the awaited future.  Offload for the
            # same event-loop reason as above.
            await ecdsa_verify_async(vk, pkt.sig, pkt.get_msg_to_sign())

        # Allow write or update.
        try:
            await verified_write_name(
                db_con,
                cur,
                self,
                pkt.behavior,
                pkt.name,
                pkt.value,
                pkt.vkc,
                pipe.route.af,
                str(IPRange(client_tup[0], bitlen=0)),
                self.sys_clock.time(),
                pkt.updated,
            )
        except ResourceLimit:
            # Indicate put failed.  Both fields are reset because the
            # client's return_resp re-converts pkt.value to None when
            # pkt.updated is 0 -- with only value cleared (and updated
            # left at the request's req_time) the client saw value=b""
            # which `is not None`, marked the put as success, and the
            # subsequent GET correctly returned no record (since the
            # row was never written). The end result was matrix tests
            # silently treating rate-limited puts as successful then
            # failing later at lookup. Setting updated=0 means the
            # client's existing `if not pkt.updated: pkt.value = None`
            # path fires and the failure becomes visible to callers.
            pkt.value = b""
            pkt.updated = 0

        await proto_send(pipe, self.serv_resp(pkt))

    async def handle_usage(self, pipe, cur, pkt, client_tup):
        """Signed-owner query for the per-IP quota state.

        Reports how many names the requesting client_ip currently
        holds against the cap, on whichever AF the request arrived
        over.  Read-only: never creates an ip row, never modifies
        anything in the db.

        Reply body: JSON-encoded
            {"af": <2|10>, "names_used": <int>, "name_limit": <int>}
        in the packet's value field.
        """
        if not pkt.vkc or not pkt.sig or not await pkt.is_valid_sig_async():
            raise PermissionError("USAGE requires valid signature")

        af = pipe.route.af

        names_used = 0
        # Only v4 ip lookup is supported in this first cut -- the v6
        # ip row keys on a 4-tuple (glob_main, glob_extra, lan_id,
        # iface_id) rather than a single integer, so a clean fetch-
        # only helper for v6 needs more plumbing.  For v6 callers the
        # response correctly reports the v6 cap but names_used=0 if
        # no row exists yet (which is the common case).
        if int(af) == int(IP4):
            sql = "SELECT id FROM ipv4s WHERE v4_val=%s"
            await cur.execute(sql, (int(IPRange(client_tup[0], bitlen=0)),))
            row = await cur.fetchone()
            if row is not None:
                ip_id = row[0]
                names_used = await get_names_used(cur, af, ip_id)

        name_limit = name_limit_by_af(af, self)

        info = {
            "af": int(af),
            "names_used": int(names_used),
            "name_limit": int(name_limit),
        }
        resp = Packet(
            op=OP_USAGE,
            name=pkt.name,
            value=json.dumps(info).encode("utf-8"),
            updated=self.sys_clock.time(),
            vkc=pkt.vkc,
            pkid=pkt.pkid,
            reply_pk=pkt.reply_pk,
        )
        await proto_send(pipe, self.serv_resp(resp))

    async def handle_del(self, pipe, cur, db_con, pkt):
        """Verify the packet signature and remove the named record from the database."""
        if not pkt.sig:
            raise PermissionError("DEL requires signature")

        # If it doesn't exist -- nothing to delete.
        row = await fetch_name(cur, pkt.name, DB_READ_LOCK)
        if row is None:
            return await proto_send(pipe, self.serv_resp(pkt))

        # Ensure signature is correct.  Offload to executor for the
        # same event-loop reason as handle_put / handle_usage.
        vk = VerifyingKey.from_string(row[3], curve=SECP256k1)
        await ecdsa_verify_async(vk, pkt.sig, pkt.get_msg_to_sign())

        # Complete delete operation.
        await verified_delete_name(db_con, cur, pkt.name)

        # Return response to sender.
        await proto_send(pipe, self.serv_resp(pkt))

    async def msg_cb(self, msg, client_tup, pipe):
        """Decrypt an incoming client message, dispatch it to the appropriate handler, and send a reply.

        Every observable failure mode is logged via aionetiface's `log()`
        so a prod operator can grep for `[serv]` lines and reconstruct
        what the server actually saw without resorting to packet captures.
        Lines include `client_tup` so per-source-IP misbehaviour is easy
        to isolate.
        """
        pkt = None
        try:
            # Decrypt and serialise packet.
            pipe.stream.set_dest_tup(client_tup)
            try:
                msg = decrypt(self.reply_sk, msg)
            except Exception as exc:
                log(fstr("[serv] DECRYPT FAIL from {0}: {1}", (client_tup, exc)))
                raise
            try:
                pkt = Packet.unpack(msg)
            except Exception as exc:
                log(fstr(
                    "[serv] UNPACK FAIL from {0} decrypted_len={1}: {2}",
                    (client_tup, len(msg), exc),
                ))
                raise

            log(fstr(
                "[serv] pkt op={0} pkid={1} updated={2} ttl={3} name_len={4} val_len={5}",
                (pkt.op, pkt.pkid, pkt.updated, pkt.ttl, pkt.name_len, pkt.value_len),
            ))

            # Validate timestamp + signed TTL of signed req.
            # The owner-chosen ttl rides inside the signed payload, so an
            # attacker can't extend the validity window by rewriting it on
            # the wire. The server still caps it at MAX_REQUEST_TTL so a
            # leaked packet can't be replayed for an unbounded time even
            # if the legitimate signer set ttl very large.
            if pkt.op != OP_GET:
                now = self.sys_clock.time()
                if pkt.updated > (now + CLOCK_SKEW_SLACK):
                    log(fstr(
                        "[serv] REJECT future updated={0} now={1} (slack={2})",
                        (pkt.updated, now, CLOCK_SKEW_SLACK),
                    ))
                    raise ValueError("Invalid future update time.")

                if pkt.ttl <= 0 or pkt.ttl > MAX_REQUEST_TTL:
                    log(fstr(
                        "[serv] REJECT ttl out of range ttl={0} max={1}",
                        (pkt.ttl, MAX_REQUEST_TTL),
                    ))
                    raise ValueError("ttl out of allowed range.")

                if (now - pkt.updated) > pkt.ttl:
                    log(fstr(
                        "[serv] REJECT expired age={0} ttl={1}",
                        (now - pkt.updated, pkt.ttl),
                    ))
                    raise ValueError("Signed request expired.")

            # Step-by-step trace -- the request sometimes silently dies
            # between the validation pass and the PUT handler with no
            # exception logged. Logging every await lets us pin the
            # exact line where execution stops.
            log(fstr("[serv] pre-mysql-connect pkid={0}", (pkt.pkid,)))
            try:
                db_con = await aiomysql.connect(
                    user=self.db_user,
                    password=self.db_pass,
                    db=self.db_name,
                    connect_timeout=10,
                )
            except Exception as exc:
                log(fstr("[serv] mysql-connect FAIL pkid={0}: {1}",
                         (pkt.pkid, exc)))
                raise
            
            log(fstr("[serv] mysql-connected pkid={0}", (pkt.pkid,)))
            try:
                async with db_con as conn_ctx:
                    log(fstr("[serv] aenter-conn pkid={0}", (pkt.pkid,)))
                    async with conn_ctx.cursor() as cur:
                        log(fstr("[serv] aenter-cursor pkid={0}", (pkt.pkid,)))

                        log(fstr(
                            "[serv] dispatch pkid={0} op={1} type={2} OP_PUT={3}",
                            (pkt.pkid, pkt.op, type(pkt.op).__name__, OP_PUT),
                        ))

                        if pkt.op == OP_GET:
                            log(fstr("[serv] GET name={0}", (pkt.name,)))
                            return await self.handle_get(pipe, cur, pkt)

                        if pkt.op == OP_PUT:
                            log(fstr(
                                "[serv] PUT name={0} from {1}",
                                (pkt.name, client_tup),
                            ))
                            ret = await self.handle_put(pipe, cur, conn_ctx, pkt, client_tup)
                            log(fstr("[serv] PUT done name={0}", (pkt.name,)))
                            return ret

                        if pkt.op == OP_DEL:
                            log(fstr("[serv] DEL name={0}", (pkt.name,)))
                            return await self.handle_del(pipe, cur, conn_ctx, pkt)

                        if pkt.op == OP_USAGE:
                            log(fstr(
                                "[serv] USAGE from {0}", (client_tup,),
                            ))
                            return await self.handle_usage(pipe, cur, pkt, client_tup)

                        log(fstr("[serv] dispatch fell-through pkid={0}", (pkt.pkid,)))
                        raise ValueError("Unknown pkt.op")
            finally:
                log(fstr("[serv] post-handler pkid={0}", (pkt.pkid,)))
                try:
                    db_con.close()
                except Exception:
                    pass
        except (OSError, ValueError, KeyError, PermissionError, BadSignatureError) as exc:
            log(fstr("[serv] HANDLED EXC for {0}: {1}", (client_tup, exc)))
            log_exception()
            error_pkt = Packet(
                OP_ERROR,
                b"Error",
                "Unknown error occured.",
                vkc=self.reply_pk,
                updated=self.sys_clock.time(),
            )

            if pkt:
                error_pkt.reply_pk = pkt.reply_pk

            try:
                await proto_send(pipe, self.serv_resp(error_pkt))
            except asyncio.CancelledError:
                raise
            except Exception as send_exc:
                log(fstr(
                    "[serv] FAILED to send error pkt to {0}: {1}",
                    (client_tup, send_exc),
                ))
        except BaseException as exc:
            # The original handler only caught the explicit list of types
            # above. Anything outside that set (e.g. mysql operational
            # errors during connect/cursor, struct errors raised before
            # the explicit except, asyncio cancellation re-raised in odd
            # places) used to bubble up and tear down the connection
            # task without sending a reply -- which manifests on the
            # client as TCP/UDP timeouts rather than an explicit
            # error_pkt. Log it so we can see when this path fires; let
            # asyncio cancellation and process-exit signals through.
            if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise
            log(fstr("[serv] UNHANDLED EXC for {0}: {1}", (client_tup, exc)))
            log_exception()


async def start_server(bind_port):
    """Load credentials from env/stdin, create a Server, and begin listening on all interfaces."""
    i = await Interface()

    # Load servers DB name.
    if "NB_DB_NAME" in os.environ:
        db_name = os.environ["NB_DB_NAME"]
    else:
        db_name = input("db name: ")

    # Load mysql root password details.
    if "NB_DB_PW" in os.environ:
        db_pass = os.environ["NB_DB_PW"]
    else:
        db_pass = input("db pass: ")

    # Load server reply public key.
    if "NB_ENC_PK" in os.environ:
        reply_pk_hex = os.environ["NB_ENC_PK"]
    else:
        reply_pk_hex = input("reply pk: ")

    # Load server reply private key
    if "NB_ENC_SK" in os.environ:
        reply_sk_hex = os.environ["NB_ENC_SK"]
    else:
        reply_sk_hex = input("reply sk: ")

    # Load server class with DB details.
    sys_clock = await SysClock(i).start()
    serv = Server(
        "root",
        db_pass,
        db_name,
        h_to_b(reply_sk_hex),
        h_to_b(reply_pk_hex),
        sys_clock,
    )

    # Start the server listening on public routes.

    for proto in [TCP, UDP]:
        await serv.listen_all(proto, bind_port, i)

    return serv


def shutdown(
    loop, sig=None
):
    """Cancel all tasks and stop the loop on SIGINT/SIGTERM."""
    if sig:
        log(fstr("Received signal {0}, shutting down...", (sig.name,)))

    try:
        pending = asyncio.all_tasks(loop)
    except AttributeError:
        pending = asyncio.Task.all_tasks(loop)

    for t in pending:
        t.cancel()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()

    # Graceful Ctrl+C / SIGTERM on all platforms.
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, shutdown, loop, sig)
            except NotImplementedError:
                pass
    # On Windows KeyboardInterrupt propagates as an exception from run_forever().

    task = loop.create_task(start_server(NB_PORT))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        shutdown(loop)
    finally:
        # Wait for all tasks to finish their CancelledError handling.
        try:
            pending = asyncio.all_tasks(loop)
        except AttributeError:
            pending = asyncio.Task.all_tasks(loop)

        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

        try:
            if hasattr(loop, "shutdown_asyncgens"):
                loop.run_until_complete(loop.shutdown_asyncgens())
            if hasattr(loop, "shutdown_default_executor"):
                loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            loop.close()
