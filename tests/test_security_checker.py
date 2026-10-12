import unittest

from security_checker import analyze_message


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


if __name__ == "__main__":
    unittest.main()