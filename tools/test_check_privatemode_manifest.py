import unittest
from unittest.mock import patch

import check_privatemode_manifest as checker


class ManifestDriftTests(unittest.TestCase):
    def test_exact_bytes_required(self):
        pinned = b'{"Policies": {"synthetic": {}}}'
        self.assertTrue(checker.compare(pinned, pinned)["match"])
        self.assertFalse(checker.compare(pinned, pinned + b"\n")["match"])
        self.assertFalse(checker.compare(pinned, b'{"Policies": {"different": {}}}')["match"])

    def test_invalid_or_oversized_fails(self):
        for body in (b"", b"no json", b"[]", b"{}", b'{"Policies": []}', b"x" * (checker.MAX_BYTES + 1)):
            with self.subTest(body_size=len(body)), self.assertRaises(ValueError):
                checker.compare(b"", body)

    def test_network_failure_is_not_success(self):
        with patch.object(checker.urllib.request, "urlopen", side_effect=OSError("sensitive detail")), patch("builtins.print") as output:
            self.assertEqual(checker.main(), 1)
        self.assertNotIn("sensitive detail", str(output.call_args_list))


if __name__ == "__main__":
    unittest.main()
