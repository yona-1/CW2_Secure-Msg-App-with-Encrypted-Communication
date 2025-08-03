import unittest
import json
from cryptography.fernet import Fernet
def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()
class TestSecureMessaging(unittest.TestCase):
    def setUp(self):
        self.key = load_key()
        self.cipher = Fernet(self.key)
    def test_encryption_decryption(self):
        msg = "Hello, this is a test!"
        encrypted = self.cipher.encrypt(msg.encode())
        decrypted = self.cipher.decrypt(encrypted).decode()
        self.assertEqual(msg, decrypted)
    def test_json_payload(self):
        payload = {"message": "Test", "timestamp": "12:00:00"}
        encrypted = self.cipher.encrypt(json.dumps(payload).encode())
        decrypted = self.cipher.decrypt(encrypted).decode()
        data = json.loads(decrypted)
        self.assertIn("message", data)
if __name__ == '__main__':
    unittest.main()