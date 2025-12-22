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
import aiomysql
from ecdsa import VerifyingKey, SECP256k1, SigningKey
from aionetiface import *
from aionetiface.utility.sys_clock import *
from aionetiface.vendor.ecies import *
from .packet import *
from .defs import *

class ResourceLimit(Exception):
    pass

async def v6_range_usage(cur, v6_glob_main, v6_glob_extra, v6_lan_id, _):
    # Count number of subnets used.
    sql  = "SELECT COUNT(DISTINCT v6_lan_id) "
    sql += "FROM ipv6s WHERE v6_glob_main=%s AND v6_glob_extra=%s FOR UPDATE"
    await cur.execute(sql, (int(v6_glob_main), int(v6_glob_extra),))
    v6_subnets_used = (await cur.fetchone())[0]

    # Count number of interfaces used.
    sql  = "SELECT COUNT(id) FROM ipv6s "
    sql += "WHERE v6_glob_main=%s AND v6_glob_extra=%s "
    sql += "AND v6_lan_id=%s FOR UPDATE"
    sql_params = (int(v6_glob_main), int(v6_glob_extra), int(v6_lan_id),)
    await cur.execute(sql, sql_params)
    v6_ifaces_used = (await cur.fetchone())[0]

    # Return results.
    return v6_subnets_used, v6_ifaces_used

async def v6_exists(cur, v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id):
    # Check if v6 subnet component exists.
    sql  = "SELECT id FROM ipv6s WHERE v6_glob_main=%s "
    sql += "AND v6_glob_extra=%s AND v6_lan_id=%s "
    sql_params = (int(v6_glob_main), int(v6_glob_extra), int(v6_lan_id),)
    await cur.execute(sql + " FOR UPDATE", sql_params)
    v6_lan_exists = (await cur.fetchone()) is not None

    # Check if IPv6 record exists.
    sql += "AND v6_iface_id=%s FOR UPDATE"
    await cur.execute(
        sql.replace(" COUNT(id) ", " id "), # Change count to select.
        (int(v6_glob_main), int(v6_glob_extra), int(v6_lan_id), int(v6_iface_id),)
    )
    v6_record = await cur.fetchone()

    # Return results.
    return v6_lan_exists, v6_record

async def v6_insert(cur, v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id, now):
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
    sql_params = (int(v6_glob_main), int(v6_glob_extra), int(v6_lan_id),)
    sql_params += (int(v6_iface_id), int(now),)
    await cur.execute(sql, sql_params)

    # Return the new row index.
    return cur.lastrowid

# Breaks down an IPv6 into fields for DB storage.
def get_v6_parts(ipr):
    ip_str = str(ipr) # Normalize IPv6.
    v6_glob_main = int(ip_str[:9].replace(':', ''), 16) # :
    v6_glob_extra = int(ip_str[10:14], 16)
    v6_lan_id = int(ip_str[15:19], 16)
    v6_iface_id = int(ip_str[20:].replace(':', ''), 16) # :
    v6_parts = (v6_glob_main, v6_glob_extra, v6_lan_id, v6_iface_id)

    return v6_parts

async def record_v6(params, serv, now):
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
        sql  = "INSERT INTO ipv4s (v4_val, timestamp) "
        sql += "VALUES (%s, %s)"
        await cur.execute(sql, (int(ipr), int(now),))
        ip_id = cur.lastrowid

    return ip_id

async def record_ip(af, params, serv, now):
    if af == IP6:
        ip_id = await record_v6(params, serv, now)
    
    # Load existing ip_id or create it - V4.
    if af == IP4:
        ip_id = await record_v4(params, serv, now)

    return ip_id

# Each IP can own X names.
# Where X depends on the address family.
def name_limit_by_af(af, serv):
    if af == IP4:
        return serv.v4_name_limit
    if af == IP6:
        return serv.v6_name_limit

async def fetch_name(cur, name, lock=DB_WRITE_LOCK):
    # Does name already exist.
    sql = "SELECT * FROM names WHERE name=%s "
    if lock == DB_WRITE_LOCK:
        sql += "FOR UPDATE"

    await cur.execute(sql, (name,))
    row = await cur.fetchone()
    return row

async def get_names_used(cur, af, ip_id):
    sql  = "SELECT COUNT(id) FROM names WHERE af=%s "
    sql += "AND ip_id=%s FOR UPDATE"
    await cur.execute(sql, (int(af), int(ip_id),))
    return (await cur.fetchone())[0]

async def record_name(cur, serv, af, ip_id, name, value, owner_pub, req_time):
    # Does name already exist.
    row = await fetch_name(cur, name)
    name_exists = row is not None

    # Get names used and limit.
    names_used = await get_names_used(cur, af, ip_id)
    name_limit = name_limit_by_af(af, serv)

    """
    The more resources a person uses for names, the less time they have to refresh
    the name. The idea is to reward conservation of resources.
    """
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
    expiry = max(int(req_time) - penalty, 0)

    # Update an existing name.
    if name_exists:
        """
        In order to prevent a name being able to be transfered to a
        different IP by simply replaying someone else's request
        we require that an update to a name change the timestamp of the req.
        Since reqs are encrypted and signed this won't be possible.
        """
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
        ret = await cur.execute(sql, 
            (
                value,
                int(af),
                int(ip_id),
                int(expiry),
                int(req_time),
                name,
                int(req_time),
            )
        )
        if not ret:
            return None

        row = (row[0], name, value, row[3], af, ip_id, expiry)
        return row

    # Create a new name.
    if not name_exists:
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
        ret = await cur.execute(sql, 
            (
                name,
                value, 
                owner_pub,
                int(af),
                int(ip_id),
                int(expiry),
                int(req_time),
            )
        )

        # Fetch the new row (so we know the ID.)
        return await fetch_name(cur, name)

# Deletes a name if a signed request is more recent.
async def verified_delete_name(db_con, cur, name):
    row = await fetch_name(cur, name)
    if row is None:
        return
        
    sql  = "DELETE FROM names WHERE "
    sql += "name = %s"
    await cur.execute(sql, (name))
    await db_con.commit()

# Prunes unneeded records from the DB.
async def verified_pruning(db_con, cur, serv, updated):
    # Delete all names that haven't been updated for X seconds.
    sql = """
    DELETE FROM names
    WHERE ((%s - timestamp) >= %s)
    """
    ret = await cur.execute(sql, (
        int(updated),
        int(serv.min_name_duration),
    ))

    # Delete all IPs that don't have associated names.
    """
    This query uses a sub-query to select all names associated
    with a specific IP address family. The parent query deletes
    all records from the IP table if no names refer back to
    an IP row. Since the name row uses a different column name
    for the id field (ip_id) the field is given an alias (id.)
    The parent query can now delete all rows that don't have
    an ID in the sub query result set.

    Note: this query could get slow with many names.
    """
    for table, af in [["ipv4s", "2"], ["ipv6s", "23"]]:
        sql = fstr("""
        DELETE FROM {0} WHERE id NOT IN (
            SELECT ip_id as id
            FROM (
                SELECT ip_id
                FROM names 
                WHERE af=%s
            ) AS results
        );
        """, (table, ))
        ret = await cur.execute(sql, (
            af,
        ))

    await db_con.commit()

async def verified_write_name(db_con, cur, serv, behavior, name, value, owner_pub, af, ip_str, now, req_time):
    # Convert ip_str into an IPRange instance.
    cidr = 32 if af == IP4 else 128
    ipr = IPRange(ip_str, cidr=cidr)

    # Unneeded records get deleted.
    if behavior != DONT_BUMP:
        await verified_pruning(db_con, cur, serv, now)

    # Record IP if needed and get its ID.
    # If it's V6 allocation limits are enforced on subnets.
    ip_id = await record_ip(af, (cur, ipr,), serv, now)
    assert(ip_id)

    # Record name if needed and get its ID.
    # Also supports transferring a name to a new IP.
    name_row = await record_name(
        cur, 
        serv, 
        af, 
        ip_id, 
        name, 
        value, 
        owner_pub,
        req_time
    )
    assert(name_row)

    # Save current changes.
    await db_con.commit()

class Server(Daemon):
    def __init__(self, db_user, db_pass, db_name, reply_sk, reply_pk, sys_clock, v4_name_limit=V4_NAME_LIMIT, v6_name_limit=V6_NAME_LIMIT, min_name_duration=MIN_NAME_DURATION, v6_addr_expiry=V6_ADDR_EXPIRY):
        self.__name__ = "NBServer"
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
        self.debug = val
        
    def set_v6_limits(self, v6_subnet_limit, v6_iface_limit):
        self.v6_subnet_limit = v6_subnet_limit
        self.v6_iface_limit = v6_iface_limit

    async def handle_get(self, pipe, cur, pkt):
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
        # Validate signature.
        if not pkt.sig or not pkt.is_valid_sig():
            raise Exception("PUT requires valid signature")

        cidr = 32 if pipe.route.af == IP4 else 128
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
                str(IPRange(client_tup[0], cidr=cidr)),
                self.sys_clock.time(),
                pkt.updated
            )
        except ResourceLimit:
            # Indicate put failed.
            pkt.value = b""

        await proto_send(pipe, self.serv_resp(pkt))

    async def handle_del(self, pipe, cur, db_con, pkt):
        if not pkt.sig:
            raise Exception("DEL requires signature")

        # If it doesn't exist -- nothing to delete.
        row = await fetch_name(cur, pkt.name, DB_READ_LOCK)
        if row is None:
            return await proto_send(pipe, self.serv_resp(pkt))

        # Ensure signature is correct.
        vk = VerifyingKey.from_string(row[3], curve=SECP256k1)
        vk.verify(pkt.sig, pkt.get_msg_to_sign())

        # Complete delete operation.
        await verified_delete_name(
            db_con,
            cur,
            pkt.name
        )

        # Return response to sender.
        await proto_send(pipe, self.serv_resp(pkt))

    async def msg_cb(self, msg, client_tup, pipe):
        db_con = None
        try:
            # Decrypt and serialise packet.
            pipe.stream.set_dest_tup(client_tup)
            msg = decrypt(self.reply_sk, msg)
            pkt = Packet.unpack(msg)

            # Validate timestamp of signed req.
            if pkt.op != OP_GET:
                now = int(self.sys_clock.time())
                if pkt.updated > (now + 5):
                    raise Exception("Invalid future update time.")
                
                if (now - 5) >= pkt.updated:
                    raise Exception("Signed request expired.")

            # Connect to local mysql server.
            db_con = await aiomysql.connect(
                user=self.db_user,
                password=self.db_pass,
                db=self.db_name,
            )

            # Handle request based on packet OP.
            async with db_con.cursor() as cur:
                if pkt.op == OP_GET:
                    return await self.handle_get(pipe, cur, pkt)

                if pkt.op == OP_PUT:
                    return await self.handle_put(
                        pipe, cur, db_con, pkt, client_tup
                    )

                if pkt.op == OP_DEL:
                    return await self.handle_del(
                        pipe, cur, db_con, pkt
                    )

                raise Exception("Unknown pkt.op")
        except Exception:
            if db_con is not None:
                await db_con.rollback()

            log_exception()
        finally:
            if db_con is not None:
                db_con.close()

async def start_server(bind_port):
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

if __name__ == "__main__": 
    loop = asyncio.get_event_loop()
    task = loop.create_task(start_server(NB_PORT))
    loop.run_forever()