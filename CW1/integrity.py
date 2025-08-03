import hashlib
import json
import os
from datetime import datetime
import mimetypes
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, filename="integrity_log.txt", filemode="a",
                    format='%(asctime)s - %(levelname)s - %(message)s')

class FileHasher:
    def __init__(self, file_path):
        self.file_path = file_path

    def generate_hash(self, algo='sha256'):
        if not os.path.exists(self.file_path):
            raise FileNotFoundError("File not found!")

        if algo.lower() == 'sha256':
            hash_obj = hashlib.sha256()
        elif algo.lower() == 'sha1':
            hash_obj = hashlib.sha1()
        elif algo.lower() == 'md5':
            hash_obj = hashlib.md5()
        else:
            raise ValueError("Unsupported hashing algorithm")

        with open(self.file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                hash_obj.update(block)

        return hash_obj.hexdigest()
    def get_metadata(self):
        size = os.path.getsize(self.file_path)
        last_modified = datetime.fromtimestamp(os.path.getmtime(self.file_path)).strftime('%Y-%m-%d %H:%M:%S')
        file_type, _ = mimetypes.guess_type(self.file_path)
        return {
            "size": size,
            "last_modified": last_modified,
            "file_type": file_type or "Unknown",
            "path": self.file_path
        }
class IntegrityChecker:
    def __init__(self, db_path="hash_records.json"):
        self.db_path = db_path
        self._ensure_db()
    def _ensure_db(self):
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'w') as f:
                json.dump({}, f)
    def save_hash(self, filepath, hashval, metadata, username):
        with open(self.db_path, 'r+') as f:
            data = json.load(f)
            data[filepath] = {
                "hash": hashval,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "user": username,
                "metadata": metadata
            }
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
        logging.info(f"Hash saved for: {filepath} by {username}")
    def verify_hash(self, filepath, current_hash):
        with open(self.db_path, 'r') as f:
            data = json.load(f)
        saved = data.get(filepath)
        if saved:
            return saved["hash"] == current_hash
        return None
    def get_metadata(self, filepath):
        with open(self.db_path, 'r') as f:
            data = json.load(f)
        return data.get(filepath, {}).get("metadata", {})
    def file_registered(self, filepath):
        with open(self.db_path, 'r') as f:
            data = json.load(f)
        return filepath in data
    def get_hash_report(self):
        with open(self.db_path, 'r') as f:
            data = json.load(f)
        return data
    def delete_record(self, filepath):
        with open(self.db_path, 'r+') as f:
            data = json.load(f)
            if filepath in data:
                del data[filepath]
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
                logging.info(f"Deleted record for: {filepath}")
                return True
            return False

