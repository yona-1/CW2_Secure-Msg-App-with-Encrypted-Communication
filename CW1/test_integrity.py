import unittest
import os
import json
from integrity import FileHasher, IntegrityChecker
class TestFileIntegrityTool(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_sample.txt"
        self.db_path = "test_hash_records.json"
        self.log_path = "test_log.txt"
        self.username = "TestUser"

        with open(self.test_file, "w") as f:
            f.write("This is a test file.")

        self.hasher = FileHasher(self.test_file)
        self.checker = IntegrityChecker(db_path=self.db_path)

    def test_hash_generation_sha256(self):
        sha256_hash = self.hasher.generate_hash('sha256')
        self.assertIsInstance(sha256_hash, str)
        self.assertEqual(len(sha256_hash), 64)

    def test_hash_generation_md5(self):
        md5_hash = self.hasher.generate_hash('md5')
        self.assertIsInstance(md5_hash, str)
        self.assertEqual(len(md5_hash), 32)
    def test_metadata_extraction(self):
        metadata = self.hasher.get_metadata()
        self.assertIn("size", metadata)
        self.assertIn("last_modified", metadata)
        self.assertIn("file_type", metadata)
    def test_save_and_verify_hash(self):
        file_hash = self.hasher.generate_hash()
        metadata = self.hasher.get_metadata()
        self.checker.save_hash(self.test_file, file_hash, metadata, self.username)

        # Should verify correctly
        self.assertTrue(self.checker.verify_hash(self.test_file, file_hash))

        # Should fail on incorrect hash
        self.assertFalse(self.checker.verify_hash(self.test_file, "wronghash123"))

    def test_get_metadata_from_checker(self):
        file_hash = self.hasher.generate_hash()
        metadata = self.hasher.get_metadata()
        self.checker.save_hash(self.test_file, file_hash, metadata, self.username)

        fetched = self.checker.get_metadata(self.test_file)
        self.assertEqual(fetched["size"], metadata["size"])
    def test_file_registered_check(self):
        self.assertFalse(self.checker.file_registered("not_exist.txt"))

        file_hash = self.hasher.generate_hash()
        metadata = self.hasher.get_metadata()
        self.checker.save_hash(self.test_file, file_hash, metadata, self.username)

        self.assertTrue(self.checker.file_registered(self.test_file))
    def test_delete_record(self):
        file_hash = self.hasher.generate_hash()
        metadata = self.hasher.get_metadata()
        self.checker.save_hash(self.test_file, file_hash, metadata, self.username)

        deleted = self.checker.delete_record(self.test_file)
        self.assertTrue(deleted)
        self.assertFalse(self.checker.file_registered(self.test_file))

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        if os.path.exists("test_log.txt"):
            os.remove("test_log.txt")


if __name__ == '__main__':
    unittest.main()