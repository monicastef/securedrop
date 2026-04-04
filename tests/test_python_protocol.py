import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_CLIENT = REPO_ROOT / "python-client"

if str(PYTHON_CLIENT) not in sys.path:
    sys.path.insert(0, str(PYTHON_CLIENT))

import protocol  # noqa: E402
1

class ProtocolHelpersTest(unittest.TestCase):
    def setUp(self):
        self._tempdir = tempfile.TemporaryDirectory()
        base = Path(self._tempdir.name)

        self._old_shared_dir = protocol.SHARED_DIR
        self._old_download_dir = protocol.DOWNLOAD_DIR
        self._old_meta_dir = protocol.META_DIR

        protocol.SHARED_DIR = base / "shared_files"
        protocol.DOWNLOAD_DIR = base / "downloads"
        protocol.META_DIR = protocol.DOWNLOAD_DIR
        protocol.SHARED_DIR.mkdir()
        protocol.DOWNLOAD_DIR.mkdir()

    def tearDown(self):
        protocol.SHARED_DIR = self._old_shared_dir
        protocol.DOWNLOAD_DIR = self._old_download_dir
        protocol.META_DIR = self._old_meta_dir
        self._tempdir.cleanup()

    def test_save_and_load_metadata_round_trip(self):
        origin_pub = b"origin-public-key"
        expected_hash = b"hash-bytes"
        sig = b"signature-bytes"

        protocol.save_metadata("note.txt", "python", origin_pub, expected_hash, sig)

        self.assertEqual(
            protocol.load_metadata("note.txt"),
            ("python", origin_pub, expected_hash, sig),
        )

    def test_list_shared_files_hides_metadata_files(self):
        (protocol.SHARED_DIR / "visible.txt").write_text("hello")
        (protocol.SHARED_DIR / "visible.txt.meta").write_text("metadata")

        self.assertEqual(protocol.list_shared_files(), ["visible.txt"])

    def test_save_and_load_download_round_trip(self):
        key = protocol.local_storage_key("python")
        data = b"encrypted download contents"

        protocol.save_download("nested/path.txt", data, key)

        self.assertEqual(protocol.load_download("path.txt", key), data)

    def test_load_download_rejects_invalid_format(self):
        (protocol.DOWNLOAD_DIR / "broken.txt").write_text("not|valid|storage")

        with self.assertRaises(ValueError):
            protocol.load_download("broken.txt", protocol.local_storage_key("python"))

    def test_local_storage_key_depends_on_identity_name(self):
        self.assertEqual(protocol.local_storage_key("alice"), protocol.local_storage_key("alice"))
        self.assertNotEqual(protocol.local_storage_key("alice"), protocol.local_storage_key("bob"))


if __name__ == "__main__":
    unittest.main()
