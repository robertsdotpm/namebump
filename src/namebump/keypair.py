from ecdsa import VerifyingKey, SECP256k1, SigningKey


class Keypair():
    def __init__(self, priv=None, pub=None):
        self.private = priv
        self.public = pub or priv.get_verifying_key()
        self.vkc = self.public.to_string("compressed")

    @staticmethod
    def generate():
        priv = SigningKey.generate(curve=SECP256k1)
        pub = priv.get_verifying_key()
        return Keypair(priv, pub)

if __name__ == "__main__":
    kp = Keypair.generate()
    print(kp.private)