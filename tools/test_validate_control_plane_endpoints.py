from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-control-plane-endpoints.py")
SPEC = importlib.util.spec_from_file_location("validate_control_plane_endpoints", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class ValidateControlPlaneEndpointsTests(unittest.TestCase):
    def test_accepts_only_canonical_origin_forms(self) -> None:
        for value in (
            "https://trustedrouter.com",
            "https://trustedrouter.com/",
            "https://trustedrouter.com:443",
        ):
            validator.validate(value)

    def test_rejects_all_known_observer_forms(self) -> None:
        for value in (
            "https://azure.trustedrouter.com/v1",
            "https://u@azure.trustedrouter.com:443/v1",
            "https://AWS.TRUSTEDROUTER.COM./v1",
            "https://aws-euw1.trustedrouter.com/v1",
            "https://aws-euw3.trustedrouter.com/v1",
            "https://status-apac.trustedrouter.com/v1",
            "https://trustedrouter.com,https://status.trustedrouter.com/v1",
            "https://aws.trustedrouter.com../v1",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validator.validate(value)

    def test_rejects_empty_or_non_https_configuration(self) -> None:
        for value in (
            "",
            " , ",
            "http://trustedrouter.com",
            "trustedrouter.com",
            "https://trustedrouter.com/v1",
            "https://trust.trustedrouter.com",
            "https://www.trustedrouter.com",
            "https://x.aws.trustedrouter.com",
            "https://billing.example",
            "https://user@trustedrouter.com",
            "https://trustedrouter.com?next=observer",
            "https://trustedrouter.com|tee-env-QUILL_API_HOST=evil.example",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validator.validate(value)


if __name__ == "__main__":
    unittest.main()
