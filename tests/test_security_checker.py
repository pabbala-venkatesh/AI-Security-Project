
import unittest
from security_checker import analyze_message, assess_risk


class TestSecurityChecker(unittest.TestCase):

    def test_detects_suspicious_phrase(self):
        result = analyze_message(
            "Urgent action required to verify your account"
        )
        self.assertTrue(result)

    def test_detects_link(self):
        result = analyze_message(
            "Please visit http://example.com"
        )
        self.assertTrue(
            any("link" in item.lower() for item in result)
        )

    def test_normal_message_has_no_warnings(self):
        result = analyze_message(
            "Your class starts at 10 AM tomorrow."
        )
        self.assertEqual(result, [])

    def test_high_risk_message(self):
        result = assess_risk(
            "URGENT ACTION REQUIRED: Verify your account "
            "at http://example.com"
        )
        self.assertEqual(result["score"], 70)
        self.assertEqual(result["level"], "High")

    def test_medium_risk_message(self):
        result = assess_risk("Verify your account")
        self.assertEqual(result["score"], 25)
        self.assertEqual(result["level"], "Medium")

    def test_low_risk_message(self):
        result = assess_risk(
            "Your class starts at 10 AM tomorrow."
        )
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "Low")


if __name__ == "__main__":
    unittest.main()
