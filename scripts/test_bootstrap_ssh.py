import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

from bootstrap_ssh import verify_proof
from origin_attestation import message, openssl_with_key


class OriginIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        # RFC 8032 test seed; never an owner or service key.
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.der = bytes.fromhex("302e020100300506032b657004220420") + seed
        self.public = openssl_with_key(["pkey", "-pubout", "-outform", "DER"], self.der)[-32:].hex()
        self.nonce = "ab" * 32
        self.host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"
        signature = openssl_with_key(["pkeyutl", "-sign", "-rawin"], self.der, message(self.nonce, self.host_key))
        self.proof = {"nonce": self.nonce, "host_key": self.host_key,
                      "public_key": self.public, "signature": signature.hex()}

    def test_accepts_identity_bound_to_this_connection(self):
        verify_proof(self.proof, self.nonce, self.host_key, self.public, self.directory)

    def test_rejects_replays_substituted_keys_and_forged_signatures(self):
        replacements = {"nonce": "cd" * 32, "host_key": "ssh-ed25519 AAAACounterfeit",
                        "public_key": "00" * 32, "signature": "00" * 64}
        for field, value in replacements.items():
            with self.subTest(field=field):
                proof = copy.deepcopy(self.proof)
                proof[field] = value
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    verify_proof(proof, self.nonce, self.host_key, self.public, self.directory)

    def test_rejects_unframed_or_injected_messages(self):
        for nonce, key in [("invalid", self.host_key), (self.nonce, self.host_key + "\ninjected")]:
            with self.assertRaises(ValueError):
                message(nonce, key)


if __name__ == "__main__":
    unittest.main()
