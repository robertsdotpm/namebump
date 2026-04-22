from typing import Optional
from ecdsa import VerifyingKey, SECP256k1, SigningKey


class Keypair:
    """ECDSA secp256k1 keypair used to sign and verify namebump requests.

    Attributes:
        private: SigningKey instance (None for verify-only use).
        public: VerifyingKey instance.
        vkc: 33-byte compressed public key (used as the owner identity on wire).
    """

    def __init__(
        self, priv: Optional[SigningKey] = None, pub: Optional[VerifyingKey] = None
    ) -> None:
        if priv is None and pub is None:
            raise ValueError("Keypair requires at least one of priv or pub")
        self.private = priv
        self.public = pub if pub is not None else priv.get_verifying_key()
        self.vkc = self.public.to_string("compressed")

    @staticmethod
    def generate() -> "Keypair":
        """Generate a new random secp256k1 keypair."""
        priv = SigningKey.generate(curve=SECP256k1)
        pub = priv.get_verifying_key()
        return Keypair(priv, pub)


if __name__ == "__main__":
    kp = Keypair.generate()
    print(kp.private)
