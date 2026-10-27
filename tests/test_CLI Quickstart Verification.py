#!/usr/bin/env python3
"""Tests for CLI Quickstart Verification."""

import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CLI_PATH = os.path.join(HERE, '..', 'src', 'pqblocks')
if not os.path.isfile(CLI_PATH):
    CLI_PATH = os.path.join(HERE, '..', 'src', 'pqblocks_core', 'pqblocks')
GOLDEN_DIR = os.path.join(HERE, 'golden')
if not os.path.isdir(GOLDEN_DIR):
    GOLDEN_DIR = os.path.join(HERE, '..', 'test', 'golden')

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

# Configure environment for child processes
ENV = os.environ.copy()
_local_lib = os.path.expanduser('~/.local/lib')
_lib_dirs = [os.path.join(HERE, '..', 'src'), _local_lib]
try:
    import pqblocks_core
    _pkg_lib = os.path.join(os.path.dirname(pqblocks_core.__file__), 'lib')
    if os.path.isdir(_pkg_lib):
        _lib_dirs.insert(0, _pkg_lib)
except ImportError:
    pass
ENV['LD_LIBRARY_PATH'] = os.pathsep.join(_lib_dirs) + os.pathsep + ENV.get('LD_LIBRARY_PATH', '')


class TestCLIQuickstartVerification(unittest.TestCase):
    """Quickstart CLI verification suite."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', self.test_dir], check=False))

    def run_cli(self, args, check=True):
        cmd = [CLI_PATH] + args
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=ENV,
            check=False
        )
        if check and res.returncode != 0:
            self.fail(f"CLI command failed: {' '.join(cmd)}\nstderr: {res.stderr}\nstdout: {res.stdout}")
        return res

    def test_cli_binary_exists_and_executable(self):
        """CLI binary must exist and be executable."""
        self.assertTrue(os.path.isfile(CLI_PATH), f"CLI binary not found at {CLI_PATH}")
        self.assertTrue(os.access(CLI_PATH, os.X_OK), f"CLI binary at {CLI_PATH} is not executable")

    def test_six_command_quickstart_sequence(self):
        """All six quickstart commands execute successfully (exit 0)."""
        kem_json = os.path.join(self.test_dir, 'kem.json')
        encaps_json = os.path.join(self.test_dir, 'encaps.json')
        shared_key = os.path.join(self.test_dir, 'shared.key')
        sig_json = os.path.join(self.test_dir, 'sig.json')
        sig_bin = os.path.join(self.test_dir, 'sig.bin')
        msg_txt = os.path.join(self.test_dir, 'msg.txt')

        with open(msg_txt, 'w') as f:
            f.write("test")

        # 1. pqblocks kem keygen --out kem.json
        r1 = self.run_cli(['kem', 'keygen', '--out', kem_json])
        self.assertEqual(r1.returncode, 0)
        self.assertTrue(os.path.exists(kem_json))

        # 2. pqblocks kem encaps --in kem.json --out encaps.json
        r2 = self.run_cli(['kem', 'encaps', '--in', kem_json, '--out', encaps_json])
        self.assertEqual(r2.returncode, 0)
        self.assertTrue(os.path.exists(encaps_json))

        # 3. pqblocks kem decaps --in encaps.json --out shared.key
        r3 = self.run_cli(['kem', 'decaps', '--in', encaps_json, '--out', shared_key])
        self.assertEqual(r3.returncode, 0)
        self.assertTrue(os.path.exists(shared_key))

        # 4. pqblocks sig keygen --out sig.json
        r4 = self.run_cli(['sig', 'keygen', '--out', sig_json])
        self.assertEqual(r4.returncode, 0)
        self.assertTrue(os.path.exists(sig_json))

        # 5. pqblocks sig sign --in sig.json --msg msg.txt --out sig.bin
        r5 = self.run_cli(['sig', 'sign', '--in', sig_json, '--msg', msg_txt, '--out', sig_bin])
        self.assertEqual(r5.returncode, 0)
        self.assertTrue(os.path.exists(sig_bin))

        # 6. pqblocks sig verify --in sig.json --msg msg.txt --sig sig.bin
        r6 = self.run_cli(['sig', 'verify', '--in', sig_json, '--msg', msg_txt, '--sig', sig_bin])
        self.assertEqual(r6.returncode, 0)
        self.assertIn("verified successfully", r6.stdout.lower())

        # Verify output lengths per spec
        with open(shared_key, 'rb') as f:
            key_data = f.read()
        self.assertEqual(len(key_data), 32, f"shared.key must be 32 bytes, got {len(key_data)}")

        with open(sig_bin, 'rb') as f:
            sig_data = f.read()
        self.assertEqual(len(sig_data), 3373, f"sig.bin must be 3373 bytes, got {len(sig_data)}")

        # Verify envelope structure in encaps.json
        with open(encaps_json, 'r') as f:
            env = json.load(f)
        self.assertEqual(env.get('kem'), 'X25519+MLKEM768')
        self.assertEqual(env.get('kdf'), 'HKDF-SHA256')
        self.assertEqual(env.get('key_confirm'), 'HMAC-SHA256')
        self.assertEqual(env.get('suite_id'), 'X25519MLKEM768-Ed25519MLDSA65-HKDF')
        self.assertEqual(env.get('version'), '1.0.0')
        self.assertEqual(env.get('ct_len'), 1120)
        self.assertEqual(env.get('ek_len'), 1216)

    def test_golden_file_decaps_and_verify(self):
        """CLI correctly operates on committed golden files."""
        golden_encaps = os.path.join(GOLDEN_DIR, 'encaps.json')
        golden_key = os.path.join(GOLDEN_DIR, 'shared.key')
        golden_sig_json = os.path.join(GOLDEN_DIR, 'sig.json')
        golden_sig_bin = os.path.join(GOLDEN_DIR, 'sig.bin')

        # Test CLI decaps against golden encaps.json
        out_key = os.path.join(self.test_dir, 'recovered.key')
        r_decaps = self.run_cli(['kem', 'decaps', '--in', golden_encaps, '--out', out_key])
        self.assertEqual(r_decaps.returncode, 0)

        with open(out_key, 'rb') as f1, open(golden_key, 'rb') as f2:
            self.assertEqual(f1.read(), f2.read(), "CLI decaps must match golden shared.key")

        # Test CLI verify against golden sig.json and sig.bin
        msg_txt = os.path.join(self.test_dir, 'msg.txt')
        with open(msg_txt, 'w') as f:
            f.write("test")

        r_verify = self.run_cli(['sig', 'verify', '--in', golden_sig_json, '--msg', msg_txt, '--sig', golden_sig_bin])
        self.assertEqual(r_verify.returncode, 0)
        self.assertIn("verified successfully", r_verify.stdout.lower())

        # Negative test: altered message must fail
        bad_msg = os.path.join(self.test_dir, 'bad_msg.txt')
        with open(bad_msg, 'w') as f:
            f.write("wrong message content")
        r_bad = self.run_cli(['sig', 'verify', '--in', golden_sig_json, '--msg', bad_msg, '--sig', golden_sig_bin], check=False)
        self.assertNotEqual(r_bad.returncode, 0, "Altered message must fail verification")


if __name__ == '__main__':
    unittest.main()
