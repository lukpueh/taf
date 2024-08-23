import pytest
from securesystemslib.exceptions import StorageError
from taf.tuf.repository import MetadataRepository
from taf.tuf.keys import load_signer_from_file

from tuf.api.metadata import TargetFile

from taf.tests.tuf import TEST_DATA_PATH


@pytest.fixture
def test_signer():
    """Create signer from some rsa test key."""
    key_path = TEST_DATA_PATH / "keystores" / "keystore" / "root1"
    return load_signer_from_file(key_path, None)


@pytest.fixture
def test_signers(test_signer):
    """Dict of signers per role"""
    signers = {}
    for role in ["root", "timestamp", "snapshot", "targets"]:
        signers[role] = [test_signer]
    return signers


class TestMetadataRepository:
    def test_open(self):
        repo = MetadataRepository(
            TEST_DATA_PATH
            / "repos"
            / "test-repository-tool"
            / "test-delegated-roles-pkcs1v15"
            / "taf"
        )

        # assert existing role metadata can be opened
        for role in [
            "root",
            "timestamp",
            "snapshot",
            "targets",
            "delegated_role1",
            "delegated_role2",
            "inner_delegated_role",
        ]:
            assert repo.open(role)

        # assert non-existing role metadata cannot be opened
        with pytest.raises(StorageError):
            repo.open("foo")

    def test_create(self, tmp_path, test_signer, test_signers):
        # Create new metadata repository
        repo = MetadataRepository(tmp_path)
        repo.signer_cache = test_signers
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

        # assert repo cannot be created twice
        with pytest.raises(FileExistsError):
            repo.create()

    def test_add_target_files(self, tmp_path, test_signers):
        """Edit metadata repository.

        If we edit manually, we need to make sure to create a valid snapshot.
        """
        # Create new metadata repository
        repo = MetadataRepository(tmp_path)
        repo.signer_cache = test_signers
        repo.create()

        target_file = TargetFile.from_data("foo.txt", b"foo", ["sha256", "sha512"])
        repo.add_target_files([target_file])

        # assert target file was adde
        assert repo.targets().targets[target_file.path] == target_file

        # assert correct versions
        assert repo.root().version == 1
        assert repo.timestamp().version == 2
        assert repo.snapshot().version == 2
        assert repo.targets().version == 2

        # assert correct snapshot and timestamp meta
        assert repo.timestamp().snapshot_meta.version == 2
        assert repo.snapshot().meta["root.json"].version == 1
        assert repo.snapshot().meta["targets.json"].version == 2
