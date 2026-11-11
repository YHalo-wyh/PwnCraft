"""China domestic CTF Pwn catalog: guard split leakage and false readiness."""
import json
from pathlib import Path
import tempfile
import unittest

from autocorrect.public_china_pwn_catalog import audit_catalog, CATALOG, SPLITS


class PublicChinaPwnCatalogTests(unittest.TestCase):
    def test_verified_repositories_and_pinned_splits(self):
        report = audit_catalog()
        self.assertTrue(report["catalog_valid"])
        self.assertEqual(report["total"], 23)
        self.assertEqual(report["by_split"], {"train": 14, "validation": 5, "frozen_test": 4})
        self.assertEqual(len(report["pending_material_import"]), 23)

    def test_reject_split_mismatch(self):
        document = json.loads(CATALOG.read_text("utf-8"))
        document["cases"][0]["split"] = "frozen_test"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "catalog.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Split not registered"):
                audit_catalog(path, SPLITS)

    def test_reject_cross_competition_leakage(self):
        document = json.loads(CATALOG.read_text("utf-8"))
        current_splits = json.loads(SPLITS.read_text("utf-8"))
        case = document["cases"][0]
        other = document["cases"][1]
        other["split"] = "validation"
        current_splits["train"] = [
            x for x in current_splits["train"] if x["case_id"] != other["case_id"]
        ]
        current_splits["validation"].append({"case_id": other["case_id"], "cluster": "test"})
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "catalog.json"
            spl = Path(temp) / "splits.json"
            path.write_text(json.dumps(document), "utf-8")
            spl.write_text(json.dumps(current_splits), "utf-8")
            with self.assertRaisesRegex(ValueError, "Cross-split competition leak"):
                audit_catalog(path, spl)


if __name__ == "__main__":
    unittest.main()
