"""
Validate the namebump runloom sync port -- plain blocking code on runloom's
M:N scheduler, reusing the aionetiface sync shims (saio + monkey + autosize)
that namebump sits on.

namebump's Server needs MySQL (aiomysql) -- infra, out of scope here -- so we
validate its deterministic, local core: keypair generation and the full
ECDSA-signed packet wire roundtrip (the security-critical part), running as
sync code.  Run: PYTHON_GIL=0 PYTHONPATH=<paths> python3.13t this.py [hubs]
"""
import sys
import time
import traceback

import runloom_boot
runloom_boot.install()

import namebump  # noqa: E402
from namebump import Keypair  # noqa: E402
from namebump.packet import Packet  # noqa: E402
from namebump.defs import OP_PUT, DO_BUMP  # noqa: E402
from aionetiface.utility.signing import ecdsa_sign_async  # noqa: E402  (now sync)
import runloom  # noqa: E402

RESULTS = []


def check(name, fn):
    """Run one check, recording (name, ok, detail)."""
    t0 = time.time()
    try:
        RESULTS.append((name, True, fn(), round(time.time() - t0, 2)))
    except BaseException:
        RESULTS.append((name, False, traceback.format_exc(), round(time.time() - t0, 2)))


def check_keypair():
    """Generate a keypair; confirm a 33-byte compressed verify key."""
    kp = Keypair.generate()
    assert isinstance(kp.vkc, bytes) and len(kp.vkc) == 33, "vkc not 33-byte compressed"
    assert kp.private and kp.public, "missing key material"
    return "keypair ok, vkc=%d bytes" % len(kp.vkc)


def check_signed_packet_roundtrip():
    """Build → sign → pack → unpack → verify a PUT packet (crypto + wire core)."""
    kp = Keypair.generate()
    name = b"runloom-test-name"
    value = b"runloom-test-value"
    pkt = Packet(OP_PUT, name, value, vkc=kp.vkc, updated=time.time(),
                 behavior=DO_BUMP, reply_pk=None, ttl=None)

    # Sign via the (now-sync) shared aionetiface ECDSA helper.
    msg = pkt.get_msg_to_sign()
    pkt.sig = ecdsa_sign_async(kp.private, msg)
    assert pkt.sig, "signing produced no signature"

    # Wire roundtrip.
    buf = pkt.pack()
    assert isinstance(buf, (bytes, bytearray)) and len(buf) > 0, "pack produced nothing"
    pkt2 = Packet.unpack(buf)

    assert pkt2.op == OP_PUT, "op did not roundtrip"
    assert pkt2.name == name, "name did not roundtrip"
    assert pkt2.value == value, "value did not roundtrip"
    assert pkt2.vkc == kp.vkc, "vkc did not roundtrip"

    # The unpacked packet's ECDSA signature must verify against its owner
    # key.  Use is_valid_sig_async -- the library's offloaded verify (what
    # the server hot-path uses): the deep-recursion ECDSA work runs on a
    # worker thread (full stack) while the goroutine parks, rather than
    # recursing on the goroutine's small C stack from a deep call chain.
    assert pkt2.is_valid_sig_async() is True, "signature failed to verify after roundtrip"

    # And a tampered packet must fail verification.
    pkt2.value = b"tampered"
    assert pkt2.is_valid_sig_async() is False, "tampered packet wrongly verified"
    return "sign+pack(%d B)+unpack+verify ok; tamper rejected" % len(buf)


def main():
    """Run namebump checks as plain sync code on the runloom scheduler."""
    check("keypair", check_keypair)
    check("signed_packet_roundtrip", check_signed_packet_roundtrip)


if __name__ == "__main__":
    hubs = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    print("=== namebump runloom sync port: runloom_boot.run(main, hubs=%d) ===" % hubs)
    runloom_boot.run(main, hubs=hubs)
    failed = 0
    for nm, ok, detail, secs in RESULTS:
        if ok:
            print("  PASS  %-26s %5.2fs  %s" % (nm, secs, detail))
        else:
            failed += 1
            print("  FAIL  %-26s %5.2fs" % (nm, secs))
            print("        " + detail.replace("\n", "\n        "))
    print("=== %d passed, %d failed ===" % (len(RESULTS) - failed, failed))
    sys.exit(1 if failed else 0)
