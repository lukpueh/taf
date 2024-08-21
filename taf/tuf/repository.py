"""TUF metadata repository"""


from pathlib import Path
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from securesystemslib.signer import Signer

from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.repository import Repository

logger = logging.getLogger(__name__)

METADATA_DIRECTORY_NAME = "metadata"


class MetadataRepository(Repository):
    """TUF metadata repository.

    Attributes:
        signer_cache: All signers available to the repository. Keys are role
            names, values are lists of signers
    """

    # TODO: define per-role expiry
    expiry_period = timedelta(days=1)

    def __init__(self, path: str) -> None:

        self.signer_cache: Dict[str, List[Signer]] = defaultdict(list)
        self._path = Path(path)

        # current snapshot version cache
        self._snapshot_info = MetaFile(1)
        # current targets infos (plus root)
        self._targets_infos: Dict[str, MetaFile] = defaultdict(lambda: MetaFile(1))

    @property
    def metadata_path(self) -> Path:
        return self._path / METADATA_DIRECTORY_NAME

    @property
    def targets_infos(self) -> Dict[str, MetaFile]:
        return self._targets_infos

    @property
    def snapshot_info(self) -> MetaFile:
        return self._snapshot_info

    def open(self, role: str) -> Metadata:
        """Return current Metadata for role from disk."""
        return Metadata.from_file(self.metadata_path / f"{role}.json")

    def close(self, role: str, md: Metadata) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        md.signed.version += 1
        md.signed.expires = datetime.now(timezone.utc) + self.expiry_period

        md.signatures.clear()
        for signer in self.signer_cache[role]:
            md.sign(signer, append=True)

        fname = f"{role}.json"

        # Default `do_snapshot` and `do_timestamp` implementations need
        # the current metadata versions
        if role == "snapshot":
            self._snapshot_info.version = md.signed.version
        elif role != "timestamp":  # role in [root, targets, <delegated targets>]
            self._targets_infos[fname].version = md.signed.version

        md.to_file(self.metadata_path / fname)
        # Store version-prefixed copy for root
        if role == "root":
            md.to_file(self.metadata_path / f"{md.signed.version}.{fname}")

    def create_repository(self):
        """Create new metadata repository.

        1. Create metadata subdir (fail, if exists)
        2. Create initial versions of top-level metadata
        3. Perform top-level delegation using keys from signer_cache.

        TODO: Should allow set threshold? Or default to 1? Or len(signers)?
        TODO: Should allow add target files?

        """
        self.metadata_path.mkdir()

        root = Root(consistent_snapshot=False)
        for role in ["root", "timestamp", "snapshot", "targets"]:
            for signer in self.signer_cache[role]:
                root.add_key(signer.public_key, role)

        for signed in [root, Timestamp(), Snapshot(), Targets()]:
            signed.version = 0  # bumps to initial valid verison 1 in `close`
            self.close(signed.type, Metadata(signed))

        self.do_snapshot()
        self.do_timestamp()
