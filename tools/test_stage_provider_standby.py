import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("stage_keys", Path(__file__).with_name("stage-provider-standby.py"))
stage_keys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_keys)
KEY = "EXAMPLE_API_KEY"
DATA = b"OTHER=keep\r\n export EXAMPLE_API_KEY = 'first'\r\nEXAMPLE_API_KEY=\"second\"\n# end"
WANT = DATA.replace(b'EXAMPLE_API_KEY="second"', b'EXAMPLE_API_KEY_STANDBY="second"')


class StandbyTest(unittest.TestCase):
    def test_preserve_and_idempotent(self):
        self.assertEqual(stage_keys.staged(DATA, KEY), (WANT, True))
        self.assertEqual(stage_keys.staged(WANT, KEY), (WANT, False))

    def test_ambiguous_inputs_are_unchanged(self):
        for bad in [DATA.replace(b"second", b"first"), DATA.replace(b"second", b""), DATA+b"\nEXAMPLE_API_KEY=third", b"EXAMPLE_API_KEY=single", DATA.replace(b"'first'",b"'a' # comment")]:
            with self.subTest():
                with self.assertRaises(ValueError):
                    stage_keys.staged(bad, KEY)

    def test_private_file_and_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "keys"
            path.write_bytes(DATA)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                stage_keys.stage(path, KEY)
            path.chmod(0o600)
            link = Path(d) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                stage_keys.stage(link, KEY)
            link.unlink()
            os.link(path, link)
            with self.assertRaises(ValueError):
                stage_keys.stage(path, KEY)
            link.unlink()
            self.assertTrue(stage_keys.stage(path, KEY))
            self.assertFalse(stage_keys.stage(path, KEY))
            self.assertEqual(path.read_bytes(), WANT)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
