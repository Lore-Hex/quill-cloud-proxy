import importlib.util
import base64
import pathlib
import sys
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("migrate-acme-cache-gcs-to-azure.py")
SPEC = importlib.util.spec_from_file_location("azure_cache_migrate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class AzureCacheMigrationTests(unittest.TestCase):
    def test_envelope_round_trip_and_binding(self) -> None:
        key = bytes(range(32))
        sealed = MODULE.seal(key, "trcache", "acme-cache", "api.example", b"certificate")
        self.assertNotIn(b"certificate", sealed)
        self.assertEqual(
            MODULE.open_envelope(key, "trcache", "acme-cache", "api.example", sealed),
            b"certificate",
        )
        with self.assertRaises(Exception):
            MODULE.open_envelope(key, "trcache", "acme-cache", "other.example", sealed)

    def test_wire_vector_matches_go_cache(self) -> None:
        sealed = MODULE.seal_with_nonce(
            bytes(range(32)),
            "trcache",
            "acme-cache",
            "api.example",
            b"certificate",
            bytes(range(12)),
        )
        self.assertEqual(
            base64.b64encode(sealed).decode(),
            "AQABAgMEBQYHCAkKCyRnpG+sg6t47DXyA9VuHTzTFI8RQ4VwJ5OO9A==",
        )

    def test_blob_url_matches_enclave_layout(self) -> None:
        self.assertEqual(
            MODULE.azure_blob_url("trcache", "acme-cache", "api.example"),
            "https://trcache.blob.core.windows.net/acme-cache/autocert-v1/YXBpLmV4YW1wbGU",
        )

    def test_migration_marker_is_nonempty_and_stable(self) -> None:
        self.assertEqual(
            MODULE.migration_marker_payload(3),
            {
                "properties": {
                    "publicAccess": "None",
                    "metadata": {
                        "trustedrouterAcmeSeedVersion": "v1",
                        "trustedrouterAcmeSeedSourceCount": "3",
                    },
                }
            },
        )
        with self.assertRaises(SystemExit):
            MODULE.migration_marker_payload(0)

    def test_request_retries_a_transient_network_failure(self) -> None:
        response = mock.MagicMock()
        entered = response.__enter__.return_value
        entered.status = 200
        entered.read.return_value = b"ok"
        with (
            mock.patch.object(
                MODULE.urllib.request,
                "urlopen",
                side_effect=[MODULE.urllib.error.URLError("temporary"), response],
            ) as urlopen,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            status, body = MODULE.request(
                "GET", "https://storage.example/object", "token"
            )
        self.assertEqual((status, body), (200, b"ok"))
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(0.25)


if __name__ == "__main__":
    unittest.main()
