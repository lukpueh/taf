"""Test HSMSigner"""

import os
import pytest

from asn1crypto.keys import (
    ECDomainParameters,
    NamedCurve,
)
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from PyKCS11 import PyKCS11

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import HSMSigner
from securesystemslib.signer._hsm_signer import PYKCS11LIB

_HSM_KEYID = 1
_HSM_USER_PIN = "123456"


def _generate_key_pair(session, keyid, curve):
    "Create ecdsa key pair on hsm"
    params = ECDomainParameters(name="named", value=NamedCurve(curve.name)).dump()

    public_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_WRAP, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
        (PyKCS11.CKA_EC_PARAMS, params),
        (PyKCS11.CKA_LABEL, curve.name),
        (PyKCS11.CKA_ID, (keyid,)),
    ]
    private_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_UNWRAP, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_LABEL, curve.name),
        (PyKCS11.CKA_ID, (keyid,)),
    ]

    session.generateKeyPair(
        public_template,
        private_template,
        mecha=PyKCS11.MechanismECGENERATEKEYPAIR,
    )


@pytest.fixture
def test_hsm(tmp_path):
    """Initialize SoftHSM token and generate ecdsa test keys"""
    so_pin = "abcd"
    token_label = "Test SoftHSM"

    # Configure SoftHSM to create test token in temporary test directory
    original_cwd = os.getcwd()
    os.chdir(tmp_path)

    with open("softhsm2.conf", "w", encoding="utf-8") as f:
        f.write("directories.tokendir = " + str(tmp_path))
    os.environ["SOFTHSM2_CONF"] = str(tmp_path / "softhsm2.conf")

    # Only load shared library after above config
    lib = PYKCS11LIB()
    slot = lib.getSlotList(tokenPresent=True)[0]
    lib.initToken(slot, so_pin, token_label)

    session = PYKCS11LIB().openSession(slot, PyKCS11.CKF_RW_SESSION)
    session.login(so_pin, PyKCS11.CKU_SO)
    session.initPin(_HSM_USER_PIN)
    session.logout()

    session.login(_HSM_USER_PIN)

    # Generate test ecdsa key pairs for curves secp256r1 and secp384r1 on test token
    _generate_key_pair(session, _HSM_KEYID, SECP256R1)

    session.logout()
    session.closeSession()

    yield

    os.chdir(original_cwd)
    del os.environ["SOFTHSM2_CONF"]


@pytest.mark.skipif(
    not os.environ.get("PYKCS11LIB"), reason="set PYKCS11LIB to SoftHSM lib path"
)
class TestHSM:
    """Test HSMSigner with SoftHSM

    Requirements:
    - install SoftHSM2
    - set environment variable ``PYKCS11LIB`` to SoftHSM library path

    See .github/workflows/hsm.yml for how this can be done on Linux, macOS and Windows.
    """

    def test_hsm(self, test_hsm):
        """Test HSM key export and signing."""

        _, key = HSMSigner.import_(_HSM_KEYID)
        signer = HSMSigner(_HSM_KEYID, {}, key, lambda sec: _HSM_USER_PIN)
        sig = signer.sign(b"DATA")
        key.verify_signature(sig, b"DATA")

        with pytest.raises(UnverifiedSignatureError):
            key.verify_signature(sig, b"NOT DATA")
