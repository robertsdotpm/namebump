from aionetiface import fstr, to_h
from ecdsa import SECP256k1, SigningKey

if __name__ == "__main__":
    print("To run your own server -- generate a key pair.")
    print("dont tell anyone else your sk though.")
    print()

    sk = SigningKey.generate(curve=SECP256k1)
    sk_buf = sk.to_string()
    vk = sk.get_verifying_key()
    vk_buf = vk.to_string("compressed")

    print(fstr("sk hex = {0}", (to_h(sk_buf),)))
    print(fstr("pk hex = {0}", (to_h(vk_buf),)))
