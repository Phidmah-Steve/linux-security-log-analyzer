
import unittest
import tempfile
from pathlib import Path
from analyzer import analyze_log


class TestSecurityLogAnalyzer(unittest.TestCase):

    def test_sample_log_counts(self):
        result = analyze_log(Path("sample_auth.log"))

        failed_by_ip, successful_by_ip, failed_total, success_total, unmatched = result

        self.assertEqual(failed_total, 8)
        self.assertEqual(success_total, 2)
        self.assertEqual(failed_by_ip["192.168.56.101"], 4)

    def test_empty_log(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "empty.log"
            log_path.write_text("", encoding="utf-8")

            result = analyze_log(log_path)

            failed_by_ip, successful_by_ip, failed_total, success_total, unmatched = result

            self.assertEqual(failed_total, 0)
            self.assertEqual(success_total, 0)
            self.assertEqual(unmatched, 0)


if __name__ == "__main__":
    unittest.main()
