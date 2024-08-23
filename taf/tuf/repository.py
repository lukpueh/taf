"""TUF metadata repository"""


from pathlib import Path
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from securesystemslib.signer import Signer, Key

from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    Targets,
    TargetFile,
    Timestamp,
)
from tuf.repository import Repository

logger = logging.getLogger(__name__)

METADATA_DIRECTORY_NAME = "metadata"


class MetadataRepository(Repository):
    """TUF metadata repository.

    Currently only support top-level delegation

    Attributes:
        signer_cache: All signers available to the repository. Keys are role
            names, values are lists of signers
    """

    # TODO: define per-role expiry
    expiry_period = timedelta(days=1)

    def __init__(self, path: Path) -> None:

        self.signer_cache: Dict[str, List[Signer]] = defaultdict(list)
        self._path = path

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

        # Needed for default `do_snapshot` and `do_timestamp` implementations
        if role == "snapshot":
            self._snapshot_info.version = md.signed.version
        elif role != "timestamp":  # role in [root, targets, <delegated targets>]
            self._targets_infos[fname].version = md.signed.version

        md.to_file(self.metadata_path / fname)
        # Store version-prefixed copy for root
        if role == "root":
            md.to_file(self.metadata_path / f"{md.signed.version}.{fname}")

    def create(self):
        """Create new metadata repository.

        1. Create metadata subdir (fail, if exists)
        2. Create initial versions of top-level metadata
        3. Perform top-level delegation using keys from signer_cache.

        TODO: Should allow pass keys?
        TODO: Should allow set threshold? Or default to 1? Or len(signers)?
        TODO: Should allow add target files?

        """
        self.metadata_path.mkdir()

        root = Root(consistent_snapshot=False)
        for role in ["root", "timestamp", "snapshot", "targets"]:
            for signer in self.signer_cache[role]:
                root.add_key(signer.public_key, role)

        sn = Snapshot()
        sn.meta["root.json"] = MetaFile(1)  # `targets.json` included per default

        for signed in [root, Timestamp(), sn, Targets()]:
            signed.version = 0  # `close` will bump to initial valid verison 1
            self.close(signed.type, Metadata(signed))

        # NOTE: No need to call do_snapshot and do_timestamp here

    def add_target_files(self, target_files: List[TargetFile]) -> None:
        """

        TODO: consider different level of abstraction. This could very well
        receive a list of paths, and source the TargetFile objects itself (see
        e.g. TargetFile.from_file). Or, not take an argument at all and just
        "sync" the files in the "targets" directory with the existing targets
        metadata.


        """
        with self.edit_targets() as targets:
            for target_file in target_files:
                targets.targets[target_file.path] = target_file

        self.do_snapshot()
        self.do_timestamp()

    def add_keys(self, keys: List[Key], role: str) -> None:
        """
        Bumps even if no or no new keys are added
        NOTE:
        """
        with self.edit_root() as root:
            for key in keys:
                root.add_key(key, role)

        if role == "targets":
            with self.edit_targets():
                pass

        # must do_snapshot change because root changed
        # if root was not part of snapshot and `role` was `timestamp` we
        # could skip do_snapshot
        self.do_snapshot()
        self.do_timestamp()
