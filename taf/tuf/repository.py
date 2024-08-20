"""TUF metadata repository"""


from pathlib import Path
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from securesystemslib.signer import CryptoSigner, Signer

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

_signed_init = {
    "root": Root,
    "snapshot": Snapshot,
    "targets": Targets,
    "timestamp": Timestamp,
}
TARGETS_DIRECTORY_NAME = "targets"
METADATA_DIRECTORY_NAME = "metadata"


class MetadataRepository(Repository):
    """TUF metadata repository

    This repository keeps the metadata for all versions of all roles in memory.
    It also keeps all target content in memory.


    Attributes:
        signer_cache: All signers available to the repository. Keys are role
            names, values are lists of signers
    """

    expiry_period = timedelta(days=1)

    def __init__(self, path: str) -> None:

        self.path = Path(path)

        self.signer_cache: Dict[str, List[Signer]] = defaultdict(list)

        # current snapshot version cache
        self._snapshot_info = MetaFile(1)
        # current targets infos (plus root)
        self._targets_infos: Dict[str, MetaFile] = defaultdict(lambda: MetaFile(1))

    @property
    def targets_path(self) -> Path:
        return self.path / TARGETS_DIRECTORY_NAME

    @property
    def metadata_path(self) -> Path:
        return self.path / METADATA_DIRECTORY_NAME

    @property
    def targets_infos(self) -> Dict[str, MetaFile]:
        return self._targets_infos

    @property
    def snapshot_info(self) -> MetaFile:
        return self._snapshot_info

    def open(self, role: str) -> Metadata:
        """Return current Metadata for role from 'storage' (or create a new one)"""
        if role == "root":
            # TODO: this doesn't look so nice
            paths = list(self.metadata_path.glob("*.root.json"))
            md_path = paths[0] if paths else None

        else:
            md_path = self.metadata_path / f"{role}.json"

        if md_path and md_path.exists():
            return Metadata.from_file(md_path)

        signed_init = _signed_init.get(role, Targets)
        md = Metadata(signed_init())

        # this makes version bumping in close() simpler
        md.signed.version = 0

        if isinstance(md, Root):
            md.consistent_snapshot = False

        return md

    def close(self, role: str, md: Metadata) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        md.signed.version += 1
        md.signed.expires = datetime.now(timezone.utc) + self.expiry_period

        md.signatures.clear()
        for signer in self.signer_cache[role]:
            md.sign(signer, append=True)

        # store new metadata version, update version caches
        self.role_cache[role].append(md)
        if role == "snapshot":
            self._snapshot_info.version = md.signed.version
        elif role != "timestamp":
            self._targets_infos[f"{role}.json"].version = md.signed.version

    def create_repository(self):
        with self.edit_root() as root:
            for role in ["root", "timestamp", "snapshot", "targets"]:
                signer = CryptoSigner.generate_ecdsa()
                self.signer_cache[role].append(signer)
                root.add_key(signer.public_key, role)

        for role in ["root", "timestamp", "snapshot", "targets"]:
            with self.edit(role):
                pass
