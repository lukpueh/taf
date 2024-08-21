import pytest
from pathlib import Path
from taf.tuf.repository import MetadataRepository
from securesystemslib.signer import CryptoSigner, SSlibKey

from cryptography.hazmat.primitives.serialization import load_pem_private_key


# TODO: de-duplicate with conftest.py constants
TEST_DATA_PATH = Path(__file__).parent.parent / "data"


@pytest.fixture
def test_signer() -> CryptoSigner:
    """Create signer from some rsa test key."""
    key_path = TEST_DATA_PATH / "keystores" / "keystore" / "root1"
    with open(key_path, "rb") as f:
        private_pem = f.read()

    priv = load_pem_private_key(private_pem, None)
    pub = SSlibKey.from_crypto(priv.public_key())
    return CryptoSigner(priv, pub)


class TestMetadataRepository:
    def test_create(self, tmp_path: Path, test_signer: CryptoSigner):
        # Create new metadata repository
        repo = MetadataRepository(tmp_path)
        for role in ["root", "timestamp", "snapshot", "targets"]:
            repo.signer_cache[role] = [test_signer]
        repo.create()

        # assert metadata files were created
        assert sorted([f.name for f in repo.metadata_path.glob("*")]) == [
            "1.root.json",
            "root.json",
            "snapshot.json",
            "targets.json",
            "timestamp.json",
        ]

        # assert correct initial version
        assert repo.root().version == 1
        assert repo.timestamp().version == 1
        assert repo.snapshot().version == 1
        assert repo.targets().version == 1

        # assert correct top-level delegation
        keyid = test_signer.public_key.keyid
        assert list(repo.root().keys.keys()) == [keyid]
        assert repo.root().roles["root"].keyids == [keyid]
        assert repo.root().roles["timestamp"].keyids == [keyid]
        assert repo.root().roles["snapshot"].keyids == [keyid]
        assert repo.root().roles["targets"].keyids == [keyid]

        # assert correct snapshot and timestamp meta
        assert repo.timestamp().snapshot_meta.version == 1
        assert repo.snapshot().meta["root.json"].version == 1
        assert repo.snapshot().meta["targets.json"].version == 1
        assert len(repo.snapshot().meta) == 2

    def test_create__fail_with_existing_repo(self, tmp_path):
        repo = MetadataRepository(tmp_path)
        repo.metadata_path.mkdir()
        with pytest.raises(FileExistsError):
            repo.create()
