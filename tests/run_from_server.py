"""
You can still flood the DB with names since min duration
feature ignores them in the count. There should be a buffer
for create to allow pending but limit it.
"""

import os
import aiomysql
from ecdsa import SigningKey, SECP256k1
import time
from aionetiface import *
from namebump import *
from namebump.server import *




"""
Don't use a fixed key so randoms can't screw with the tests.
Not that you want to run this on production anyway.
"""
NB_LOCAL_SK = Keypair.generate()
NB_TEST_PORT = NB_PORT
NB_TEST_ENC_PK = b'\x03\x85\x97u\xb1z\xcf\xbb\xf0U0!\x9d\xe9\x8bI\xbc\xf10\xba1\xd4\xa2k\xdb\xbd\xddy\xb7\x07\x94\n\xd8'
NB_TEST_ENC_SK = b'\x98\x0b\x0e\xfb\x99\xa0\xab\xf8t\x10\xb9\xaf\x10\x97\xb3\xaaI\xa4!@\xfc\xfbZ\xeftO\t)km\x9bi'
NB_TEST_DB_PASS = ""
NB_TEST_NAME = b"NB_test_name"
NB_TEST_VALUE = b"NB_test_value"
NB_TEST_DB_USER = "root"
NB_TEST_DB_NAME = "pnp"
NB_TEST_IPS = {IP4: "127.0.0.1", IP6: "::1"}

if "NB_DB_PW" in os.environ:
    NB_TEST_DB_PASS = os.environ["NB_DB_PW"]
else:
    NB_TEST_DB_PASS = input("db pass: ")


async def NB_clear_tables():
    db_con = await aiomysql.connect(
        user=NB_TEST_DB_USER, 
        password=NB_TEST_DB_PASS,
        db=NB_TEST_DB_NAME
    )

    async with db_con.cursor() as cur:
        await cur.execute("DELETE FROM names WHERE 1=1")
        await cur.execute("DELETE FROM ipv4s WHERE 1=1")
        await cur.execute("DELETE FROM ipv6s WHERE 1=1")
        await db_con.commit()
        
    db_con.close()

async def NB_get_test_client_serv(v4_name_limit=V4_NAME_LIMIT, v6_name_limit=V6_NAME_LIMIT, min_name_duration=MIN_NAME_DURATION, v6_serv_ips=None, v6_addr_expiry=V6_ADDR_EXPIRY, i=Interface("default")):
    sys_clock = SysClock(i, ntp=1766450948)
    loop = asyncio.get_event_loop()
    #loop.register_clock(sys_clock)
    #sys_clock.time = time.time
    serv = Server(
        NB_TEST_DB_USER,
        NB_TEST_DB_PASS,
        NB_TEST_DB_NAME,
        NB_TEST_ENC_SK,
        NB_TEST_ENC_PK,
        sys_clock,
        v4_name_limit,
        v6_name_limit,
        min_name_duration,
        v6_addr_expiry
    )
    
    # Bind to loop back or specific IP6.
    if v6_serv_ips is None:
        await serv.listen_loopback(TCP, NB_TEST_PORT, i)
    else:
        route = await i.route(IP6).bind(ips=v6_serv_ips, port=NB_TEST_PORT)
        await serv.add_listener(TCP, route)
    #await serv.listen_all(UDP, NB_TEST_PORT, i)



    clients = {}
    for af in VALID_AFS:
        dest = (NB_TEST_IPS[af], NB_TEST_PORT)
        if af is IP6 and v6_serv_ips is not None:
            dest = (v6_serv_ips, NB_TEST_PORT)
            
        clients[af] = await Client(dest, NB_TEST_ENC_PK, sys_clock, i)

    return clients, serv

class TestPNPFromServer(unittest.IsolatedAsyncioTestCase):
    async def test_NB_non_ascii_io(self):
        clients, serv = await NB_get_test_client_serv()
        await NB_clear_tables()

        # Generate mostly the full range of bytes.
        buf = b""
        for i in range(1, 255):
            buf += bytes([i])

        # Test store and get.
        for af in VALID_AFS:
            client = clients[af]
            await client.put(
                NB_TEST_NAME,
                buf,
                NB_LOCAL_SK
            )

            pkt = await client.get(NB_TEST_NAME)
            assert(pkt.value == buf)

        await serv.close()

    async def test_NB_prune(self):
        clients, serv = await NB_get_test_client_serv()
        await NB_clear_tables()



        # Make all v6 addresses expire.
        serv.v6_addr_expiry = 0

        await clients[IP6].put(
            NB_TEST_NAME,
            NB_TEST_VALUE,
            NB_LOCAL_SK
        )

        db_con = await aiomysql.connect(
            user=NB_TEST_DB_USER, 
            password=NB_TEST_DB_PASS,
            db=NB_TEST_DB_NAME
        )

        # Will delete the ipv6 value as it expires.
        # The name remains unaffected.
        async with db_con.cursor() as cur:
            updated = serv.sys_clock.time()
            await verified_pruning(db_con, cur, serv, updated)
            await db_con.commit()

        # Make all names expire.
        # Don't make the address expire this time.
        serv.min_name_duration = 0
        serv.v6_addr_expiry = 10000000

        # Will create a new ipv6 and name entry.
        await clients[IP6].put(
            NB_TEST_NAME + b"2",
            NB_TEST_VALUE,
            NB_LOCAL_SK
        )

        """
        All names should expire leaving a lone ip with no name.
        Then the final clause will run and sweep up that IP
        since it has no attached names.
        """
        async with db_con.cursor() as cur:
            updated = serv.sys_clock.time()
            await verified_pruning(db_con, cur, serv, updated)
            await db_con.commit()

        # After everything runs both tables should be empty.
        async with db_con.cursor() as cur:
            for t in ["ipv6s", "names"]:
                sql = f"SELECT COUNT(*) FROM {t} WHERE 1=1"
                await cur.execute(sql)
                no = (await cur.fetchone())[0]
                assert(no == 0)

        db_con.close()
        await serv.close()

    async def test_NB_val_sqli(self):
        evil_val = b"testvalue'); DROP TABLE names; --"
        clients, serv = await NB_get_test_client_serv()
        for af in VALID_AFS: # VALID_AFS
            await NB_clear_tables()

            # Do insert.
            await clients[af].put(
                NB_TEST_NAME,
                evil_val,
                NB_LOCAL_SK
            )

            ret = await clients[af].get(NB_TEST_NAME)
            assert(ret.value == evil_val)

        await serv.close()

    async def test_NB_insert_fetch_del(self):
        clients, serv = await NB_get_test_client_serv()
        for af in VALID_AFS: # VALID_AFS
            await NB_clear_tables()

            # Do insert.
            await clients[af].put(
                NB_TEST_NAME,
                NB_TEST_VALUE,
                NB_LOCAL_SK
            )

            # Test value was stored by retrieval.
            ret = await clients[af].get(NB_TEST_NAME)
            update_x = ret.updated
            assert(ret.value == NB_TEST_VALUE)
            #assert(ret.vkc == clients[af].reply_pk)

            # Ensure new timestamp greater than old.
            await asyncio.sleep(2)

            # Do update.
            await clients[af].put(
                NB_TEST_NAME,
                NB_TEST_VALUE + b"changed",
                NB_LOCAL_SK
            )

            # Test value was stored by retrieval.
            ret = await clients[af].get(NB_TEST_NAME, NB_LOCAL_SK)
            update_y = ret.updated
            assert(ret.value == (NB_TEST_VALUE + b"changed"))
            assert(ret.vkc == NB_LOCAL_SK.vkc)

            # NOTE: Later update times are less due to penalty calculations.
            # Expected behavior as far as I can think.
            #assert(update_y < update_x)

            # Now delete the value.
            ret = await clients[af].delete(NB_TEST_NAME, NB_LOCAL_SK)
            assert(ret.vkc == NB_LOCAL_SK.vkc)

            # Test value was deleted.
            ret = await clients[af].get(NB_TEST_NAME)
            assert(ret.value == None)
            assert(ret.vkc == clients[af].reply_pk)

        await serv.close()

    async def test_NB_migrate_name_afs(self):
        async def is_af_valid(af):
            sql = "SELECT * FROM names WHERE name=%s AND af=%s"
            db_con = await aiomysql.connect(
                user=NB_TEST_DB_USER, 
                password=NB_TEST_DB_PASS,
                db=NB_TEST_DB_NAME
            )

            is_valid = False
            async with db_con.cursor() as cur:
                await cur.execute(sql, (NB_TEST_NAME, int(af)))
                row = await cur.fetchone()
                is_valid = row is not None

            db_con.close()
            return is_valid

        await NB_clear_tables()
        clients, serv = await NB_get_test_client_serv()


        for af_x in VALID_AFS:
            # Ensure time stamp of next put is always in the future.
            await asyncio.sleep(1)

            # Create the ini-tial value.
            await clients[af_x].put(
                NB_TEST_NAME,
                NB_TEST_VALUE,
                NB_LOCAL_SK
            )

            # Ensure AF is valid.
            is_valid = await is_af_valid(af_x)
            assert(is_valid)

            # Migrate the name to a different address.
            for af_y in VALID_AFS:
                if af_x == af_y:
                    continue

                # New signed updates need a higher time stamp.

                await asyncio.sleep(2)

                # Do the migration.
                await clients[af_y].put(
                    NB_TEST_NAME,
                    NB_TEST_VALUE,
                    NB_LOCAL_SK
                )

                # Ensure the AF is valid.
                is_valid = await is_af_valid(af_y)
                assert(is_valid)

                # Test fetch.
                ret = await clients[af_y].get(NB_TEST_NAME)
                assert(ret.value == NB_TEST_VALUE)

        await serv.close()

    async def test_NB_name_pop_works(self):
        # Set test params needed for test
        vectors = [
            [IP4, 3],
            [IP6, 3]
        ]

        # 0, 1, 2 ... oldest = 0
        # 1, 2, 3 (oldest is popped)
        for af, name_limit in vectors:
            await NB_clear_tables()
            clients, serv = await NB_get_test_client_serv(3, 3, 4)

            # Fill the stack.
            for i in range(0, name_limit):
                await clients[af].put(f"{i}", "val", NB_LOCAL_SK)
                await asyncio.sleep(1)

            # Other names expire here.
            await asyncio.sleep(3)

            # Now pop the oldest.
            await clients[af].put(f"3", "val", NB_LOCAL_SK)
            ret = await clients[af].get(f"3")
            assert(ret.value == b"val")

            # Cleanup server.
            await serv.close()

    async def test_NB_freshness_limit(self):
        # Connect to local mysql server.
        """
        db_con = await aiomysql.connect(
            user=NB_TEST_DB_USER, 
            password=NB_TEST_DB_PASS,
            db=NB_TEST_DB_NAME
        )

        # Handle request based on packet OP.
        async with db_con.cursor() as cur:
            sql = "INSERT INTO ipv6s 
            (
                v6_glob_main,
                v6_glob_extra,
                v6_lan_id,
                v6_iface_id,
                timestamp
            )
            VALUES (%s, %s, %s, %s, %s)
            "
            await cur.execute(sql, (0, 0, 0, 1, int(time.time()) ))

            sql = "SELECT * FROM ipv6s"
            await cur.execute(sql)
            rows = await cur.fetchall()
            print(rows)
        """


        name_limit = 3     
        for af in VALID_AFS:
            await NB_clear_tables()
            clients, serv = await NB_get_test_client_serv(name_limit, name_limit)

            # Fill the stack past name_limit.
            for i in range(1, name_limit + 2):
                try:
                    await clients[af].put(f"{i}", "val", NB_LOCAL_SK)
                except KeyError:
                    pass

                await asyncio.sleep(1)

            # Check values still exist.
            for i in range(1, name_limit + 1):
                ret = await clients[af].get(f"{i}")
                assert(ret.value == b"val")

            # Check insert over limit rejected.
            ret = await clients[af].get("4")
            assert(ret.value == None)
            await serv.close()

    async def test_bump_exception(self):
        name_limit = 1
        for af in VALID_AFS:
            await NB_clear_tables()
            clients, serv = await NB_get_test_client_serv(name_limit, name_limit)

            await clients[af].put("a", "val", NB_LOCAL_SK)

            throw_set = False
            try:
                await clients[af].put("b", "val", NB_LOCAL_SK, THROW_BUMP)
            except KeyError:
                throw_set = True

            assert(throw_set)
            await serv.close()

    async def test_NB_respect_owner_access(self):
        i = await Interface("default")
        _, serv = await NB_get_test_client_serv()

        alice = {}
        bob = {}
        sys_clock = SysClock(i, ntp=1766450948)

        for af in VALID_AFS:
            dest = (NB_TEST_IPS[af], NB_TEST_PORT)
            alice[af] = await Client(dest, NB_TEST_ENC_PK, sys_clock, i)
            alice[af].kp = Keypair.generate()
            bob[af] = await Client(dest, NB_TEST_ENC_PK, sys_clock, i)
            bob[af].kp = Keypair.generate()

        test_name = b"some_name"
        alice_val = b"alice_val"
        for af in VALID_AFS:
            await NB_clear_tables()

            assert(alice[af].kp.vkc != bob[af].kp.vkc)
            await alice[af].put(test_name, alice_val, alice[af].kp)
            await asyncio.sleep(2)

            # Bob tries to write to alices name with incorrect sig.
            await bob[af].put(test_name, b"changed val", bob[af].kp)
            await asyncio.sleep(2)

            # The changes aren't saved then.
            ret = await bob[af].get(test_name)
            assert(ret.value == alice_val)

        await serv.close()

    async def test_NB_polite_no_bump(self):
        name_limit = 3
        for af in VALID_AFS:
            await NB_clear_tables()
            clients, serv = await NB_get_test_client_serv(name_limit, name_limit, 4)

            # Fill up the name queue.
            for i in range(0, name_limit):
                await clients[af].put(f"{i}", f"{i}", NB_LOCAL_SK, DONT_BUMP)
                await asyncio.sleep(2)

            # Ols names expire.
            await asyncio.sleep(3)

            # Normally this would bump one.
            await clients[af].put(f"3", f"3", NB_LOCAL_SK, DONT_BUMP)
            ret = await clients[af].get(f"3")
            assert(ret.value == None)

            # All original values should exist.
            for i in range(0, name_limit):
                ret = await clients[af].get(f"{i}")
                assert(ret.value == to_b(f"{i}"))

            await serv.close() 

    """
ip address add fe80:3456:7890:1111:0000:0000:0000:0001/128 dev ens192
ip address add fe80:3456:7890:1111:0000:0000:0000:0002/128 dev ens192
ip address add fe80:3456:7890:1111:0000:0000:0000:0003/128 dev ens192
ip address add fe80:3456:7890:2222:0000:0000:0000:0001/128 dev ens192
ip address add fe80:3456:7890:2222:0000:0000:0000:0002/128 dev ens192
ip address add fe80:3456:7890:2222:0000:0000:0000:0003/128 dev ens192
ip address add fe80:3456:7890:3333:0000:0000:0000:0001/128 dev ens192

New-NetIPAddress -InterfaceIndex 4 -IPAddress "fe80:3456:7890:1111:0000:0000:0000:0001" -PrefixLength 128 -AddressFamily IPv6 -Type Unicast
New-NetIPAddress -InterfaceIndex 4 -IPAddress "fe80:3456:7890:1111:0000:0000:0000:0002" -PrefixLength 128 -AddressFamily IPv6 -Type Unicast
New-NetIPAddress -InterfaceIndex 4 -IPAddress "fe80:3456:7890:1111:0000:0000:0000:0003" -PrefixLength 128 -AddressFamily IPv6 -Type Unicast
New-NetIPAddress -InterfaceIndex 4 -IPAddress "fe80:3456:7890:2222:0000:0000:0000:0001" -PrefixLength 128 -AddressFamily IPv6 -Type Unicast
New-NetIPAddress -InterfaceIndex 4 -IPAddress "fe80:3456:7890:2222:0000:0000:0000:0002" -PrefixLength 128 -AddressFamily IPv6 -Type Unicast
New-NetIPAddress -InterfaceIndex 4 -IPAddress "fe80:3456:7890:2222:0000:0000:0000:0003" -PrefixLength 128 -AddressFamily IPv6 -Type Unicast
New-NetIPAddress -InterfaceIndex 4 -IPAddress "fe80:3456:7890:3333:0000:0000:0000:0001" -PrefixLength 128 -AddressFamily IPv6 -Type Unicast
    """
    async def test_NB_v6_range_limits(self):
        # Subnet limit = 2
        # Iface limit = 2
        await NB_clear_tables()
        i = await Interface() # Needed for link local to work
        clients, serv = await NB_get_test_client_serv(v6_serv_ips="fe80:3456:7890:1111:0000:0000:0000:0001", i=i)
        serv.set_v6_limits(2, 2)

        vectors = [
            # Exhaust iface limit:
            [
                # glob          net  iface
                "fe80:3456:7890:1111:0000:0000:0000:0001",
                b"0"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:1111:0000:0000:0000:0002",
                b"1"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:1111:0000:0000:0000:0003",
                None
            ],

            # Exhaust subnet limit.
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0001",
                b"3"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0002",
                b"4"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0003",
                None
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:3333:0000:0000:0000:0001",
                None
            ],
        ]

        for offset in range(0, len(vectors)):
            src_ip, expect = vectors[offset]
            client = clients[IP6]

            # Patch client pipe to use a specific fixed IP.
            async def get_dest_pipe():
                # Bind to specific local IP.
                route = client.nic.route(IP6)
                await route.bind(ips=src_ip)

                # Return a pipe to the PNP server.
                pipe = await Pipe(
                    TCP,
                    client.addr,
                    route
                ).connect()

                return pipe

            # Patch the client to use specific src ip.
            client.get_dest_pipe = get_dest_pipe

            # Test out the vector.
            await client.put(f"{offset}", f"{offset}", NB_LOCAL_SK)
            await asyncio.sleep(2)
            ret = await client.get(f"{offset}")
            if ret.value is None:
                assert(expect is None)
            else:
                assert(expect == to_b(f"{offset}"))

        # Cleanup.
        await serv.close()

    async def test_v6_no_name_ip_prune(self):
        await NB_clear_tables()
        i = await Interface()
        clients, serv = await NB_get_test_client_serv(
            v6_serv_ips="fe80:3456:7890:1111:0000:0000:0000:0001",
            v6_name_limit=10,
            i=i
        )
        serv.set_v6_limits(3, 3)

        vectors = [
            # Exhaust subnet limit.
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0001",
                b"0"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0002",
                b"1"
            ],
            [
                # glob          net  iface
                "fe80:3456:7890:2222:0000:0000:0000:0003",
                b"2"
            ],
        ]

        client = clients[IP6]
        for offset in range(0, len(vectors)):
            src_ip, expect = vectors[offset]

            # Patch client pipe to use a specific fixed IP.
            async def get_dest_pipe():
                # Bind to specific local IP.
                route = client.nic.route(IP6)
                await route.bind(ips=src_ip)

                # Return a pipe to the PNP server.
                pipe = await Pipe(
                    TCP,
                    client.addr,
                    route
                ).connect()

                return pipe

            # Patch the client to use specific src ip.
            client.get_dest_pipe = get_dest_pipe

            # Test out the vector.
            await client.put(f"{offset}", f"{offset}", NB_LOCAL_SK)
            await asyncio.sleep(2)
            ret = await client.get(f"{offset}")
            if ret.value is None:
                assert(expect is None)
            else:
                assert(expect == to_b(f"{offset}"))

        db_con = await aiomysql.connect(
            user=NB_TEST_DB_USER, 
            password=NB_TEST_DB_PASS,
            db=NB_TEST_DB_NAME
        )

        async with db_con.cursor() as cur:
            await cur.execute("SELECT COUNT(id)FROM ipv6s WHERE 1=1")
            ret = (await cur.fetchone())[0]
            assert(ret == len(vectors))

        db_con.close()

        for offset in range(0, len(vectors)):
            await client.delete(f"{offset}", NB_LOCAL_SK)

        # Should delete all past ipv6s not associated with a name.
        await client.put("new", "something", NB_LOCAL_SK)

        db_con = await aiomysql.connect(
            user=NB_TEST_DB_USER, 
            password=NB_TEST_DB_PASS,
            db=NB_TEST_DB_NAME
        )

        async with db_con.cursor() as cur:
            await cur.execute("SELECT COUNT(id)FROM ipv6s WHERE 1=1")
            ret = (await cur.fetchone())[0]
            assert(ret == 1)

        db_con.close()

        # Cleanup.
        await serv.close()



if __name__ == '__main__':
    # Load mysql root password details.
    if "NB_DB_PW" in os.environ:
        NB_TEST_DB_PASS = os.environ["NB_DB_PW"]
    else:
        NB_TEST_DB_PASS = input("db pass: ")

    main()