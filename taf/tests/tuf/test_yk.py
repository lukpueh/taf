"""Test YkSigner"""

import os
import pytest

from taf.tuf.keys import YkSigner

from securesystemslib.exceptions import UnverifiedSignatureError


class TestYkSigner:
    """Test YkSigner"""

    @pytest.mark.skipif(
        not os.environ.get("REAL_YK"),
        reason="Enable with REAL_YK env var (test prompts for pin)",
    )
    def test_real_yk(self):
        """Test Yubikey public key export and signing with real Yubikey
        NOTE: test will prompt for a pin.
        """
        from getpass import getpass

        def sec_handler(secret_name: str) -> str:
            return getpass(f"Enter {secret_name}: ")

        key = YkSigner.import_()
        signer = YkSigner(key, sec_handler)

        sig = signer.sign(b"DATA")
        key.verify_signature(sig, b"DATA")
        with pytest.raises(UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")
