"""Coverage ledger: byte hashing, extraction methods, and skipped/incomplete inputs."""
from collections import Counter
import hashlib


def sha256_buffer(data, check=None):
    digest = hashlib.sha256()
    for offset in range(0, len(data), 1024**2):
        if check:
            check()
        digest.update(data[offset:offset + 1024**2])
    return digest.hexdigest()


class Coverage:
    def __init__(self):
        self.entries = []
        self.inventory_complete = True
        self.omitted_records = 0

    def add(self, path, size, status="scanned", kind="file", reason="", **extra):
        row = {"value": path, "source": path, "line": None, "offset": None,
               "kind": kind, "status": status, "size": size, "reason": reason,
               "evidence": reason or "See extraction methods and hash coverage; no semantic completeness guarantee.",
               "methods": [], "bytes_hashed": 0, **extra}
        if len(self.entries) < 100000:
            self.entries.append(row)
        else:
            self.omitted_records += 1
            self.inventory_complete = False
        if status in {"unexpanded", "inventory_incomplete"}:
            self.inventory_complete = False
        return row

    def summary(self):
        leaves = [x for x in self.entries if x["kind"] == "file"]
        return {
            "inventory_complete_within_opened_inputs": self.inventory_complete,
            "records": len(self.entries), "omitted_records": self.omitted_records,
            "file_statuses": dict(Counter(x["status"] for x in leaves)),
            "file_bytes_hashed": sum(x["bytes_hashed"] for x in leaves),
            "enumerated_file_bytes": sum(x["size"] or 0 for x in leaves),
            "fully_hashed_files": sum(x.get("sha256") is not None and x["bytes_hashed"] == x["size"] for x in leaves),
            "semantic_completeness_guaranteed": False,
            "note": "Hashes cover the bytes read, not decrypted or understood logic. Nested-container bytes are excluded from leaf byte totals. Unexpanded archives may hide additional files. A scanned file can have bounded or string-only extraction.",
        }
