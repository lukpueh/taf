"""TUF metadata key functions.

"""


from typing import Optional

from pathlib import Path
from securesystemslib.signer import (
    Key,
    SSlibKey,
    CryptoSigner,
    Signer,
    SecretsHandler,
    Signature,
)
from securesystemslib.formats import encode_canonical
from securesystemslib.hash import digest

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from taf.yubikey import export_piv_pub_key, sign_piv_rsa_pkcs1v15


def _get_legacy_keyid(key: SSlibKey) -> str:
    """Computes legacy keyid as hash over an opinionated canonical
    representation of the public key."""
    data = encode_canonical(
        {
            "keytype": key.keytype,
            "scheme": key.scheme,
            "keyval": {"public": key.keyval["public"].strip()},
            "keyid_hash_algorithms": ["sha256", "sha512"],
        }
    ).encode("utf-8")
    hasher = digest("sha256")
    hasher.update(data)
    return hasher.hexdigest()


def _from_crypto(pub: RSAPublicKey) -> SSlibKey:
    """Converts pyca/cryptography public key to SSlibKey with default signing
    scheme and legacy keyid."""
    # securesystemslib does not (yet) check if keytype and scheme are compatible
    # https://github.com/secure-systems-lab/securesystemslib/issues/766
    if not isinstance(pub, RSAPublicKey):
        raise ValueError(f"keytype '{type(pub)}' not supported")
    key = SSlibKey.from_crypto(pub, scheme="rsa-pkcs1v15-sha256")
    key.keyid = _get_legacy_keyid(key)
    return key


def load_public_key_from_file(path: Path) -> SSlibKey:
    """Load SSlibKey from RSA public key file.

    * Expected key file format is SubjectPublicKeyInfo/PEM
    * Signing scheme defaults to 'rsa-pkcs1v15-sha256'
    * Keyid is computed from legacy canonical representation of public key

    """
    with open(path, "rb") as f:
        pem = f.read()

    pub = load_pem_public_key(pem)
    return _from_crypto(pub)


def load_signer_from_file(path: Path, password: Optional[str]) -> CryptoSigner:
    """Load CryptoSigner from RSA private key file.

    * Expected key file format is PKCS8/PEM
    * Signing scheme defaults to 'rsa-pkcs1v15-sha256'
    * Keyid is computed from legacy canonical representation of public key
    * If password is None, the key is expected to be unencrypted

    """
    with open(path, "rb") as f:
        pem = f.read()

    priv = load_pem_private_key(pem, password)
    pub = priv.public_key()
    return CryptoSigner(priv, _from_crypto(pub))


class YkSigner(Signer):
    _SECRET_PROMPT = "pin"

    def __init__(self, public_key: Key, pin_handler: SecretsHandler):

        self._public_key = public_key
        self.pin_handler = pin_handler

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def import_(cls) -> SSlibKey:
        pem = export_piv_pub_key()
        # FIXME: unecessary pem serialization->deserialization detour:
        # export could return pyca/crypto pub object right away
        pub = load_pem_public_key(pem)
        return _from_crypto(pub)

    def sign(self, payload: bytes) -> Signature:
        pin = self.pin_handler(self._SECRET_PROMPT)
        # FIXME: RuntimeError (generator didn't yield) in _yk_piv_ctrl, if keys match
        # sig = sign_piv_rsa_pkcs1v15(payload, pin, self.public_key.keyval["public"])
        sig = sign_piv_rsa_pkcs1v15(payload, pin)
        return Signature(self.public_key.keyid, sig.hex())

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "Signer":
        # See https://python-securesystemslib.readthedocs.io/en/latest/signer.html
        # for from_priv_key_uri usage.
        raise NotImplementedError
