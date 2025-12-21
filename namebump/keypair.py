from ecdsa import VerifyingKey, SECP256k1, SigningKey


class Keypair():
    def __init__(self, priv=None, pub=None):
        self.private = priv
        self.public = pub

    @staticmethod
    def generate():
        priv = SigningKey.generate(curve=SECP256k1)
        pub = priv.get_verifying_key().to_string("compressed")
        return Keypair(priv, pub)

if __name__ == "__main__":
    kp = Keypair.generate()
    print(kp.private)