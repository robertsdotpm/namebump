from p2pd import *
from ecdsa import SigningKey, SECP256k1
import hashlib

#     python -W ignore::ResourceWarning your_script.py
NIC_NAME = ""

class TestStatus(unittest.IsolatedAsyncioTestCase):

    async def test_pnp_client(self):
        hosts = [0, 1]
        nic = await Interface(NIC_NAME)
        sys_clock = await SysClock(nic, ntp=0.1)

        # Pub key crap -- used for signing PNP messages.
        # Pub key will be used as a static name for testing too.
        install_path = get_p2pd_install_root()
        sk = load_signing_key(NODE_PORT, install_path)

        # Try all IPs and AFs.
        name = sk.verifying_key.to_string("compressed")
        name = hashlib.sha256(name).hexdigest()[:25]
        for af in nic.supported():
            for host in hosts:
                serv = PNP_SERVERS[af][host]
                dest = (serv["ip"], serv["port"])
                client = PNPClient(
                    sk=sk,
                    dest=dest,
                    dest_pk=h_to_b(serv["pk"]),
                    nic=nic,
                    sys_clock=sys_clock,
                )

                failed = False
                val = rand_plain(10)

                calls = [
                    (client.push, (name, val,)),
                    (client.fetch, (name,)),
                    (client.delete, (name,)),
                    (client.fetch, (name,)),
                ]

                out = None
                failed = False
                for call in calls:
                    f, args = call
                    out = await f(*args)
                    if out is None:
                        print(fstr("pnp {0} {1} {2} failed", (str(f), af, dest,)))
                        failed = True
                    else:
                        print(fstr("pnp {0} {1} {2} {3} ok", (str(f), af, dest, out.value)))
                
                if out is not None:
                    if out.value == val:
                        failed = True

                if not failed:
                    print(fstr("pnp {0} {1} success", (af, dest,)))

        
if __name__ == '__main__':
    main()