#!/usr/bin/env python3
"""Tests for CLI Tool."""

import json
import os
import subprocess
import tempfile
import unittest

# Path to the CLI tool binary (to be built)
HERE = os.path.dirname(os.path.abspath(__file__))
CLI_PATH = os.path.join(HERE, '..', 'src', 'pqblocks')
if not os.path.isfile(CLI_PATH):
    CLI_PATH = os.path.join(HERE, '..', 'src', 'pqblocks_core', 'pqblocks')
if not os.path.isfile(CLI_PATH):
    try:
        import pqblocks_core, shutil
        for name in ('pqblocks', 'pqblocks_core'):
            _pkg_bin = os.path.join(os.path.dirname(pqblocks_core.__file__), name)
            if os.path.isfile(_pkg_bin):
                CLI_PATH = _pkg_bin
                break
            _which_bin = shutil.which(name)
            if _which_bin:
                CLI_PATH = _which_bin
                break
    except ImportError:
        pass

if os.path.isfile(CLI_PATH) and not os.access(CLI_PATH, os.X_OK):
    try:
        os.chmod(CLI_PATH, 0o755)
    except OSError:
        pass

# Set LD_LIBRARY_PATH so the CLI can find the shared libraries
_local_lib = os.path.expanduser('~/.local/lib')
_lib_dirs = [os.path.join(HERE, '..', 'src'), _local_lib]
try:
    import pqblocks_core
    _pkg_lib = os.path.join(os.path.dirname(pqblocks_core.__file__), 'lib')
    if os.path.isdir(_pkg_lib):
        _lib_dirs.insert(0, _pkg_lib)
except ImportError:
    pass
os.environ['LD_LIBRARY_PATH'] = os.pathsep.join(_lib_dirs) + os.pathsep + os.environ.get('LD_LIBRARY_PATH', '')


class TestPQBlocksCLI(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', self.test_dir], check=False))

    def run_pqblocks(self, args, input_data=None, check=True):
        """Run the pqblocks CLI with given arguments."""
        cmd = [CLI_PATH] + args
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=False,  # We'll handle bytes ourselves
                check=check,
            )
            return result
        except FileNotFoundError:
            self.fail(f"CLI tool not found at {CLI_PATH}. Please build it first.")
        except subprocess.CalledProcessError as e:
            return e

    def test_kem_keygen_creates_valid_json(self):
        """Test that `pqblocks kem keygen --out file` creates a JSON file with all spec fields."""
        out_file = os.path.join(self.test_dir, 'kem.json')
        result = self.run_pqblocks(['kem', 'keygen', '--out', out_file])
        self.assertEqual(result.returncode, 0, f"kem keygen failed: {result.stderr.decode()}")

        # Check the output file exists and is valid JSON
        self.assertTrue(os.path.exists(out_file))
        with open(out_file, 'r') as f:
            data = json.load(f)

        # Check required fields from spec §8 and quickstart
        self.assertEqual(data.get('kem'), 'X25519+MLKEM768')
        # kem.json is KEM-only output; sig field is not present
        self.assertEqual(data.get('kdf'), 'HKDF-SHA256')
        self.assertEqual(data.get('key_confirm'), 'HMAC-SHA256')
        self.assertEqual(data.get('suite_id'), 'X25519MLKEM768-Ed25519MLDSA65-HKDF')
        self.assertEqual(data.get('version'), '1.0.0')
        self.assertEqual(data.get('ct_len'), 1120)
        self.assertEqual(data.get('ek_len'), 1216)

    def test_kem_encaps_decaps_roundtrip(self):
        """Test that kem encaps followed by decaps recovers the shared secret."""
        kem_file = os.path.join(self.test_dir, 'kem.json')
        enc_file = os.path.join(self.test_dir, 'encaps.json')
        key_file = os.path.join(self.test_dir, 'shared.key')

        # Generate key
        result1 = self.run_pqblocks(['kem', 'keygen', '--out', kem_file])
        self.assertEqual(result1.returncode, 0)

        # Encapsulate
        result2 = self.run_pqblocks(['kem', 'encaps', '--in', kem_file, '--out', enc_file])
        self.assertEqual(result2.returncode, 0, f"kem encaps failed: {result2.stderr.decode()}")

        # Check encaps.json has required envelope fields
        self.assertTrue(os.path.exists(enc_file))
        with open(enc_file, 'r') as f:
            enc_data = json.load(f)
        self.assertEqual(enc_data.get('kem'), 'X25519+MLKEM768')
        self.assertEqual(enc_data.get('ct_len'), 1120)
        self.assertEqual(enc_data.get('ek_len'), 1216)

        # Decapsulate
        result3 = self.run_pqblocks(['kem', 'decaps', '--in', enc_file, '--out', key_file])
        self.assertEqual(result3.returncode, 0, f"kem decaps failed: {result3.stderr.decode()}")

        # Check that the shared key file is 32 bytes
        self.assertTrue(os.path.exists(key_file))
        with open(key_file, 'rb') as f:
            key_data = f.read()
        self.assertEqual(len(key_data), 32, f"Shared key should be 32 bytes, got {len(key_data)}")

    def test_sig_keygen_sign_verify_roundtrip(self):
        """Test that sig keygen, sign, and verify work correctly."""
        sig_file = os.path.join(self.test_dir, 'sig.json')
        sig_bin_file = os.path.join(self.test_dir, 'sig.bin')
        msg_file = os.path.join(self.test_dir, 'msg.txt')

        # Create a message file
        with open(msg_file, 'wb') as f:
            f.write(b'test message')

        # Generate key
        result1 = self.run_pqblocks(['sig', 'keygen', '--out', sig_file])
        self.assertEqual(result1.returncode, 0)

        # Check sig.json has all required envelope fields per spec §8 and §12
        with open(sig_file, 'r') as f:
            sig_data = json.load(f)
        self.assertEqual(sig_data.get('sig'), 'Ed25519+MLDSA65')
        self.assertEqual(sig_data.get('construction'), 'CompositeAlgorithmSignatures2025')
        self.assertEqual(sig_data.get('composite_sig_len'), 3373)
        self.assertEqual(sig_data.get('euf_cma'), True)
        self.assertEqual(sig_data.get('suf_cma'), False)
        self.assertEqual(sig_data.get('ctx_label'), 'ML-DSA-65')
        self.assertEqual(sig_data.get('sig_len'), 3373)
        self.assertEqual(sig_data.get('kem'), 'X25519+MLKEM768')
        self.assertEqual(sig_data.get('kdf'), 'HKDF-SHA256')
        self.assertEqual(sig_data.get('key_confirm'), 'HMAC-SHA256')
        self.assertEqual(sig_data.get('suite_id'), 'X25519MLKEM768-Ed25519MLDSA65-HKDF')
        self.assertEqual(sig_data.get('version'), '1.0.0')

        # Sign
        result2 = self.run_pqblocks(['sig', 'sign', '--in', sig_file, '--msg', msg_file, '--out', sig_bin_file])
        self.assertEqual(result2.returncode, 0, f"sig sign failed: {result2.stderr.decode()}")

        # Verify
        result3 = self.run_pqblocks(['sig', 'verify', '--in', sig_file, '--msg', msg_file, '--sig', sig_bin_file])
        self.assertEqual(result3.returncode, 0, f"sig verify failed: {result3.stderr.decode()}")

        # Check that the signature file is 3373 bytes
        self.assertTrue(os.path.exists(sig_bin_file))
        with open(sig_bin_file, 'rb') as f:
            sig_data = f.read()
        self.assertEqual(len(sig_data), 3373, f"Signature should be 3373 bytes, got {len(sig_data)}")

    def test_error_cases(self):
        """Test that error cases are handled correctly."""
        # Test with non-existent input file
        result = self.run_pqblocks(['kem', 'encaps', '--in', '/nonexistent.json', '--out', 'out.json'], check=False)
        self.assertNotEqual(result.returncode, 0)

        # Test with missing required arguments
        result = self.run_pqblocks(['kem', 'keygen'], check=False)
        self.assertNotEqual(result.returncode, 0)

        # Test with unknown command
        result = self.run_pqblocks(['unknown'], check=False)
        self.assertNotEqual(result.returncode, 0)

        # Test sig verify with tampered signature should fail
        sig_file = os.path.join(self.test_dir, 'sig.json')
        sig_bin_file = os.path.join(self.test_dir, 'sig.bin')
        msg_file = os.path.join(self.test_dir, 'msg.txt')
        with open(msg_file, 'wb') as f:
            f.write(b'test message')
        self.run_pqblocks(['sig', 'keygen', '--out', sig_file])
        self.run_pqblocks(['sig', 'sign', '--in', sig_file, '--msg', msg_file, '--out', sig_bin_file])
        # Tamper the signature by flipping a byte
        with open(sig_bin_file, 'rb') as f:
            sig_bytes = bytearray(f.read())
        sig_bytes[0] ^= 0xFF  # Flip bits
        tampered_file = os.path.join(self.test_dir, 'tampered.sig')
        with open(tampered_file, 'wb') as f:
            f.write(sig_bytes)
        result = self.run_pqblocks(['sig', 'verify', '--in', sig_file, '--msg', msg_file, '--sig', tampered_file], check=False)
        self.assertNotEqual(result.returncode, 0, "Tampered signature should fail verification")

    def test_full_quickstart_sequence(self):
        """Test the full quickstart sequence from spec §12."""
        kem_file = os.path.join(self.test_dir, 'kem.json')
        enc_file = os.path.join(self.test_dir, 'encaps.json')
        key_file = os.path.join(self.test_dir, 'shared.key')
        sig_file = os.path.join(self.test_dir, 'sig.json')
        sig_bin_file = os.path.join(self.test_dir, 'sig.bin')
        msg_file = os.path.join(self.test_dir, 'msg.txt')

        # Create a message file
        with open(msg_file, 'wb') as f:
            f.write(b'test message')

        # All six commands must succeed (exit code 0)
        r1 = self.run_pqblocks(['kem', 'keygen', '--out', kem_file])
        self.assertEqual(r1.returncode, 0)
        r2 = self.run_pqblocks(['kem', 'encaps', '--in', kem_file, '--out', enc_file])
        self.assertEqual(r2.returncode, 0)
        r3 = self.run_pqblocks(['kem', 'decaps', '--in', enc_file, '--out', key_file])
        self.assertEqual(r3.returncode, 0)
        r4 = self.run_pqblocks(['sig', 'keygen', '--out', sig_file])
        self.assertEqual(r4.returncode, 0)
        r5 = self.run_pqblocks(['sig', 'sign', '--in', sig_file, '--msg', msg_file, '--out', sig_bin_file])
        self.assertEqual(r5.returncode, 0)
        r6 = self.run_pqblocks(['sig', 'verify', '--in', sig_file, '--msg', msg_file, '--sig', sig_bin_file])
        self.assertEqual(r6.returncode, 0)

        # Verify output lengths
        with open(key_file, 'rb') as f:
            self.assertEqual(len(f.read()), 32, "Shared key must be 32 bytes")
        with open(sig_bin_file, 'rb') as f:
            self.assertEqual(len(f.read()), 3373, "Signature must be 3373 bytes")


if __name__ == '__main__':
    unittest.main()