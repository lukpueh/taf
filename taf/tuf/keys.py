from pathlib import Path
from securesystemslib.signer import SSlibKey, CryptoSigner
from securesystemslib.formats import encode_canonical
from securesystemslib.hash import digest

from cryptography.hazmat.primitives.serialization import load_pem_private_key


def get_legacy_keyid(key: SSlibKey) -> str:
    data = encode_canonical(
        {
            "keytype": key.keytype,
            "scheme": key.scheme,
            "keyval": key.keyval,
            "keyid_hash_algorithms": ["sha256", "sha512"],
        }
    ).encode("utf-8")
    hasher = digest("sha256")
    hasher.update(data)
    return hasher.hexdigest()


def load_signer_from_file(path: Path, password: str) -> CryptoSigner:
    """Load rsa signer from path pkcs8/pem format"""
    with open(path, "rb") as f:
        private_pem = f.read()

    priv = load_pem_private_key(private_pem, password)
    pub = SSlibKey.from_crypto(priv.public_key())
    pub.keyid = get_legacy_keyid(pub)
    print(pub.keyid)
    return CryptoSigner(priv, pub)
