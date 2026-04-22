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
import signal
import asyncio
import aiomysql
from typing import Any, Optional, Tuple
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
from aionetiface.vendor.ecies import encrypt, decrypt
from .packet import Packet
from .defs import (
    OP_GET,
    OP_PUT,
    OP_DEL,
    OP_ERROR,
    V4_NAME_LIMIT,
    V6_NAME_LIMIT,
    MIN_NAME_DURATION,
    MIN_DURATION_PENALTY,
    V6_SUBNET_LIMIT,
    V6_IFACE_LIMIT,
    V6_ADDR_EXPIRY,
    NB_PORT,
    DONT_BUMP,
)


class ResourceLimit(Exception):
    """Raised when a per-IP name or address allocation limit is exceeded."""


async def v6_range_usage(
    cur: Any, v6_glob_main: int, v6_glob_extra: int, v6_lan_id: int, _: Any
) -> Tuple[int, int]:
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
    cur: Any, v6_glob_main: int, v6_glob_extra: int, v6_lan_id: int, v6_iface_id: int
) -> Tuple[bool, Optional[Any]]:
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
    cur: Any,
    v6_glob_main: int,
    v6_glob_extra: int,
    v6_lan_id: int,
    v6_iface_id: int,
    now: float,
) -> int:
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
    )
    sql_params += (
        int(v6_iface_id),
        now,
    )
    await cur.execute(sql, sql_params)

    # Return the new row index.
    return cur.lastrowid


def get_v6_parts(ipr: Any) -> Tuple[int, int, int, int]:
    """Break down an IPv6 address into (glob_main, glob_extra, lan_id, iface_id) for DB storage."""
    ip_str = str(ipr)  # Normalize IPv6.
    v6_glob_main = int(ip_str[:9].replace(":", ""), 16)  # :
    v6_glob_extra = int(ip_str[10:14], 16)
    v6_lan_id = int(ip_str[15:19], 16)
    v6_iface_id = int(ip_str[20:].replace(":", ""), 16)  # :
    v6_parts = (v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id)

    return v6_parts


async def record_v6(params: Tuple[Any, ...], serv: Any, now: float) -> int:
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


async def record_v4(params: Tuple[Any, ...], serv: Any, now: float) -> int:
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


async def record_ip(af: Any, params: Tuple[Any, ...], serv: Any, now: float) -> int:
    """Dispatch to the AF-specific IP recorder and return the resulting row ID."""
    if af == IP6:
        return await record_v6(params, serv, now)

    # Load existing ip_id or create it - V4.
    if af == IP4:
        return await record_v4(params, serv, now)

    raise ValueError("Unsupported address family: {}".format(af))


def name_limit_by_af(af: Any, serv: Any) -> int:
    """Return the per-IP name limit for the given address family."""
    if af == IP4:
        return serv.v4_name_limit
    if af == IP6:
        return serv.v6_name_limit
    raise ValueError("Unsupported address family: {}".format(af))


async def fetch_name(cur: Any, name: bytes, lock: Any = DB_WRITE_LOCK) -> Optional[Any]:
    """Fetch a name row from the DB, optionally locking it for write."""
    # Does name already exist.
    if lock == DB_WRITE_LOCK:
        sql = "SELECT * FROM names WHERE name=%s FOR UPDATE"
    else:
        sql = "SELECT * FROM names WHERE name=%s"

    await cur.execute(sql, (name,))
    row = await cur.fetchone()
    return row


async def get_names_used(cur: Any, af: Any, ip_id: int) -> int:
    """Return the count of names currently owned by a given IP row."""
    sql = "SELECT id FROM names WHERE af=%s AND ip_id=%s FOR UPDATE"
    await cur.execute(sql, (int(af), int(ip_id)))
    rows = await cur.fetchall()
    return len(rows)


async def record_name(
    cur: Any,
    serv: Any,
    af: Any,
    ip_id: int,
    name: bytes,
    value: bytes,
    owner_pub: bytes,
    req_time: float,
) -> Optional[Any]:
    """Insert or update a name record, enforcing limits and applying freshness penalties."""
    # Does name already exist.
    row = await fetch_name(cur, name)
    name_exists = row is not None

    # Get names used and limit.
    names_used = await get_names_used(cur, af, ip_id)
    name_limit = name_limit_by_af(af, serv)

    # Penalty: the more names an IP holds, the shorter the refresh window.
    # This rewards conservation of the shared name namespace.
    if names_used:
        if names_used >= name_limit:
            p_names_used = 1
        else:
            p_names_used = names_used / name_limit

        penalty = int(MIN_NAME_DURATION * p_names_used) + 1
        penalty = max(penalty, MIN_DURATION_PENALTY)
    else:
        penalty = 0

    # Apply penalty given req_time.
    expiry = max(req_time - penalty, 0)

    # Update an existing name.
    if name_exists:
        # Guard against replay attacks: require that the timestamp on the
        # update differs from the stored one.  Because requests are signed
        # and encrypted, a replayed packet cannot forge a new timestamp.
        sql = """
        UPDATE names SET 
        value=%s,
        af=%s,
        ip_id=%s,
        timestamp=%s,
        updated=%s
        WHERE name=%s 
        AND updated != %s
        """
        ret = await cur.execute(
            sql,
            (
                value,
                int(af),
                int(ip_id),
                expiry,
                req_time,
                name,
                req_time,
            ),
        )
        if not ret:
            return None

        row = (row[0], name, value, row[3], af, ip_id, expiry)
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


async def verified_delete_name(db_con: Any, cur: Any, name: bytes) -> None:
    """Delete a name record from the DB if it exists, then commit."""
    row = await fetch_name(cur, name)
    if row is None:
        await db_con.rollback()  # Nothing to do
        return

    sql = "DELETE FROM names WHERE name = %s"
    await cur.execute(sql, (name,))
    await db_con.commit()  # Commit success


async def verified_pruning(db_con: Any, cur: Any, serv: Any, updated: float) -> None:
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
    for table, af in [["ipv4s", "2"], ["ipv6s", "10"]]:
        sql = fstr(
            """
        DELETE FROM {0} WHERE id NOT IN (
            SELECT ip_id as id
            FROM (
                SELECT ip_id
                FROM names 
                WHERE af=%s
            ) AS results
        );
        """,
            (table,),
        )
        await cur.execute(sql, (af,))


async def verified_write_name(
    db_con: Any,
    cur: Any,
    serv: Any,
    behavior: int,
    name: bytes,
    value: bytes,
    owner_pub: bytes,
    af: Any,
    ip_str: str,
    now: float,
    req_time: float,
) -> None:
    """Record or update a name-to-IP mapping, optionally pruning stale records first."""
    # Convert ip_str into an IPRange instance.
    host_limit = 0
    ipr = IPRange(ip_str, bitlen=host_limit)

    # Unneeded records get deleted.
    if behavior != DONT_BUMP:
        # If this fails, the whole transaction rolls back
        await verified_pruning(db_con, cur, serv, now)

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
        db_user: str,
        db_pass: str,
        db_name: str,
        reply_sk: bytes,
        reply_pk: bytes,
        sys_clock: Any,
        v4_name_limit: int = V4_NAME_LIMIT,
        v6_name_limit: int = V6_NAME_LIMIT,
        min_name_duration: int = MIN_NAME_DURATION,
        v6_addr_expiry: int = V6_ADDR_EXPIRY,
    ) -> None:
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

    def serv_resp(self, pkt: Packet) -> bytes:
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

    def set_debug(self, val: bool) -> None:
        """Enable or disable verbose debug output."""
        self.debug = val

    def set_v6_limits(self, v6_subnet_limit: int, v6_iface_limit: int) -> None:
        """Set per-subnet and per-interface IPv6 registration limits."""
        self.v6_subnet_limit = v6_subnet_limit
        self.v6_iface_limit = v6_iface_limit

    async def handle_get(self, pipe: Any, cur: Any, pkt: Packet) -> None:
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
        self, pipe: Any, cur: Any, db_con: Any, pkt: Packet, client_tup: Tuple[str, int]
    ) -> None:
        """Validate the packet signature and write or update a name record in the database."""
        # Validate signature.
        if not pkt.sig or not pkt.is_valid_sig():
            raise PermissionError("PUT requires valid signature")

        # Ensure signature for update is correct.
        row = await fetch_name(cur, pkt.name, DB_READ_LOCK)
        if row:
            vk = VerifyingKey.from_string(row[3], curve=SECP256k1)
            vk.verify(pkt.sig, pkt.get_msg_to_sign())

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
            # Indicate put failed.
            pkt.value = b""

        await proto_send(pipe, self.serv_resp(pkt))

    async def handle_del(self, pipe: Any, cur: Any, db_con: Any, pkt: Packet) -> None:
        """Verify the packet signature and remove the named record from the database."""
        if not pkt.sig:
            raise PermissionError("DEL requires signature")

        # If it doesn't exist -- nothing to delete.
        row = await fetch_name(cur, pkt.name, DB_READ_LOCK)
        if row is None:
            return await proto_send(pipe, self.serv_resp(pkt))

        # Ensure signature is correct.
        vk = VerifyingKey.from_string(row[3], curve=SECP256k1)
        vk.verify(pkt.sig, pkt.get_msg_to_sign())

        # Complete delete operation.
        await verified_delete_name(db_con, cur, pkt.name)

        # Return response to sender.
        await proto_send(pipe, self.serv_resp(pkt))

    async def msg_cb(self, msg: bytes, client_tup: Tuple[str, int], pipe: Any) -> None:
        """Decrypt an incoming client message, dispatch it to the appropriate handler, and send a reply."""
        pkt = None
        try:
            # Decrypt and serialise packet.
            pipe.stream.set_dest_tup(client_tup)
            msg = decrypt(self.reply_sk, msg)
            pkt = Packet.unpack(msg)

            # Validate timestamp of signed req.
            if pkt.op != OP_GET:
                now = self.sys_clock.time()
                if pkt.updated > (now + 5):
                    raise ValueError("Invalid future update time.")

                if (now - 5) >= pkt.updated:
                    raise ValueError("Signed request expired.")

            # Connect to local mysql server; __aexit__ closes it automatically.
            async with await aiomysql.connect(
                user=self.db_user,
                password=self.db_pass,
                db=self.db_name,
            ) as db_con:
                # Handle request based on packet OP.
                async with db_con.cursor() as cur:
                    if pkt.op == OP_GET:
                        return await self.handle_get(pipe, cur, pkt)

                    if pkt.op == OP_PUT:
                        return await self.handle_put(pipe, cur, db_con, pkt, client_tup)

                    if pkt.op == OP_DEL:
                        return await self.handle_del(pipe, cur, db_con, pkt)

                    raise ValueError("Unknown pkt.op")
        except (OSError, ValueError, KeyError, PermissionError, BadSignatureError):
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

            await proto_send(pipe, self.serv_resp(error_pkt))


async def start_server(bind_port: int) -> "Server":
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
    print("Now starting namebump serv on ...")
    print(reply_pk_hex)

    for proto in [TCP, UDP]:
        await serv.listen_all(proto, bind_port, i)

    return serv


def shutdown(
    loop: asyncio.AbstractEventLoop, sig: Optional[signal.Signals] = None
) -> None:
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
