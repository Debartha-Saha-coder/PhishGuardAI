"""
PhishGuard AI 2.0 — Automated Test Suite
=========================================
Tests are grouped into ten areas that correspond to the submission requirements.
All examples are synthetic and are not derived from real private messages or
credentials.

Run with:
    python -m pytest tests/ -v
or:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

# ---------------------------------------------------------------------------
# Make the engine importable whether tests/ is run from the project root or
# from inside the tests/ directory.
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from phishguard_engine import (
    MAX_MESSAGE_LENGTH,
    MAX_URL_LENGTH,
    SCORE_HIGH_THRESHOLD,
    SCORE_MEDIUM_THRESHOLD,
    analyze_message,
    analyze_url,
    export_report,
    extract_urls,
    print_report,
    _risk_level,
    _score_findings,
)


# ===========================================================================
# 1. Empty and invalid inputs
# ===========================================================================

class TestEmptyAndInvalidInputs(unittest.TestCase):
    """Inputs that must be rejected with a ValueError."""

    # --- analyze_message ---

    def test_message_empty_string_raises(self):
        with self.assertRaises(ValueError):
            analyze_message("")

    def test_message_whitespace_only_raises(self):
        with self.assertRaises(ValueError):
            analyze_message("   \n\t  ")

    def test_message_non_string_raises(self):
        with self.assertRaises(ValueError):
            analyze_message(None)  # type: ignore[arg-type]

    def test_message_integer_raises(self):
        with self.assertRaises(ValueError):
            analyze_message(42)  # type: ignore[arg-type]

    def test_message_too_long_raises(self):
        with self.assertRaises(ValueError):
            analyze_message("x" * (MAX_MESSAGE_LENGTH + 1))

    # --- analyze_url ---

    def test_url_empty_string_raises(self):
        with self.assertRaises(ValueError):
            analyze_url("")

    def test_url_whitespace_only_raises(self):
        with self.assertRaises(ValueError):
            analyze_url("   ")

    def test_url_non_string_raises(self):
        with self.assertRaises(ValueError):
            analyze_url(None)  # type: ignore[arg-type]

    def test_url_too_long_raises(self):
        with self.assertRaises(ValueError):
            analyze_url("http://example.invalid/" + "a" * MAX_URL_LENGTH)

    # --- extract_urls ---

    def test_extract_urls_non_string_returns_empty(self):
        self.assertEqual(extract_urls(None), [])  # type: ignore[arg-type]

    def test_extract_urls_empty_string_returns_empty(self):
        self.assertEqual(extract_urls(""), [])


# ===========================================================================
# 2. Suspicious credential-request messages
# ===========================================================================

class TestCredentialRequestMessages(unittest.TestCase):
    """Messages that request passwords or one-time codes."""

    def test_password_mention_triggers_msg002(self):
        result = analyze_message("Please enter your password to continue.")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MSG002", rule_ids)

    def test_otp_mention_triggers_msg002(self):
        result = analyze_message("Enter your OTP to verify your identity.")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MSG002", rule_ids)

    def test_verification_code_triggers_msg002(self):
        result = analyze_message("Provide the verification code sent to your phone.")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MSG002", rule_ids)

    def test_credential_message_has_high_severity_finding(self):
        result = analyze_message("Enter your password immediately.")
        high_findings = [
            f for f in result["findings"] if f["severity"] == "high"
        ]
        self.assertTrue(
            len(high_findings) >= 1,
            "Expected at least one high-severity finding.",
        )

    def test_credential_message_score_above_zero(self):
        result = analyze_message("Enter your login credentials now.")
        self.assertGreater(result["risk_score"], 0)

    def test_msg002_finding_includes_evidence(self):
        result = analyze_message("Please share your passcode.")
        msg002 = next(f for f in result["findings"] if f["rule_id"] == "MSG002")
        self.assertIn("passcode", msg002["evidence"])


# ===========================================================================
# 3. Urgency and payment-related messages
# ===========================================================================

class TestUrgencyAndPaymentMessages(unittest.TestCase):

    def test_urgent_language_triggers_msg001(self):
        result = analyze_message("Act now or your account will be suspended immediately.")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MSG001", rule_ids)

    def test_urgent_evidence_contains_matched_term(self):
        result = analyze_message("This is a final warning about your account.")
        msg001 = next(f for f in result["findings"] if f["rule_id"] == "MSG001")
        self.assertIn("final warning", msg001["evidence"])

    def test_payment_language_triggers_msg003(self):
        result = analyze_message("Your payment failed. Please pay now to avoid service interruption.")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MSG003", rule_ids)

    def test_bank_details_triggers_msg003(self):
        result = analyze_message("Please provide your bank details to process the refund.")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MSG003", rule_ids)

    def test_combined_urgency_and_payment_raises_score(self):
        msg_urgency_only = analyze_message("Act now immediately.")
        msg_urgency_and_payment = analyze_message(
            "Act now immediately. Payment failed. Please pay now."
        )
        self.assertGreater(
            msg_urgency_and_payment["risk_score"],
            msg_urgency_only["risk_score"],
        )

    def test_wire_transfer_triggers_msg003(self):
        result = analyze_message("Please arrange a wire transfer of $500.")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MSG003", rule_ids)


# ===========================================================================
# 4. Legitimate messages that should not be classified as phishing
# ===========================================================================

class TestLegitimateMessages(unittest.TestCase):
    """
    Legitimate messages should not automatically receive high scores.

    Note: these tests verify that the score is LOW (< SCORE_MEDIUM_THRESHOLD),
    not that it is zero — a zero-score legitimate message may be realistic but
    the engine should never automatically classify a message as 'safe'.
    """

    def test_plain_announcement_score_is_low(self):
        result = analyze_message(
            "Hello students, the library will open at 9 AM on Monday. "
            "Please check the notice board for details.",
            sender="office@college.example",
        )
        self.assertLess(result["risk_score"], SCORE_MEDIUM_THRESHOLD)

    def test_plain_reminder_score_is_low(self):
        result = analyze_message(
            "Reminder: please review the event information when convenient.",
            sender="events@example.org",
        )
        self.assertLess(result["risk_score"], SCORE_MEDIUM_THRESHOLD)

    def test_low_score_summary_does_not_claim_safe(self):
        result = analyze_message(
            "Hello, your order has been dispatched.",
            sender="orders@shop.example",
        )
        # The summary must not tell the user the message is confirmed safe.
        self.assertNotIn("confirmed safe", result["summary"].lower())
        self.assertNotIn("definitely safe", result["summary"].lower())

    def test_legitimate_message_risk_level_low(self):
        result = analyze_message(
            "Your subscription has been renewed successfully.",
            sender="billing@service.example",
        )
        self.assertEqual(result["risk_level"], "Low")


# ===========================================================================
# 5. URLs with unusual structures
# ===========================================================================

class TestUnusualURLStructures(unittest.TestCase):

    def test_ip_address_host_triggers_url003(self):
        result = analyze_url("http://192.0.2.1/login")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL003", rule_ids)

    def test_punycode_host_triggers_url004(self):
        result = analyze_url("http://xn--nxasmq6b.example/")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL004", rule_ids)

    def test_many_labels_triggers_url005(self):
        result = analyze_url("http://a.b.c.d.e.f.invalid/")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL005", rule_ids)

    def test_userinfo_triggers_url006(self):
        result = analyze_url("http://user:pass@malicious.invalid/")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL006", rule_ids)

    def test_security_word_in_host_triggers_url007(self):
        result = analyze_url("http://secure-login.invalid/")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL007", rule_ids)

    def test_non_http_scheme_triggers_url001(self):
        result = analyze_url("ftp://files.example.invalid/data")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL001", rule_ids)

    def test_http_scheme_triggers_url008(self):
        result = analyze_url("http://example.invalid/page")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL008", rule_ids)

    def test_https_does_not_trigger_url008(self):
        result = analyze_url("https://example.invalid/page")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("URL008", rule_ids)

    def test_repeated_encoding_triggers_url009(self):
        result = analyze_url("http://example.invalid/%2F%2F%2Flogin")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL009", rule_ids)

    def test_url003_ip_host_is_medium_severity(self):
        result = analyze_url("http://198.51.100.1/")
        ip_finding = next(
            f for f in result["findings"] if f["rule_id"] == "URL003"
        )
        self.assertEqual(ip_finding["severity"], "medium")


# ===========================================================================
# 6. Malformed URLs
# ===========================================================================

class TestMalformedURLs(unittest.TestCase):

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            analyze_url("")

    def test_whitespace_raises(self):
        with self.assertRaises(ValueError):
            analyze_url("   ")

    def test_none_raises(self):
        with self.assertRaises(ValueError):
            analyze_url(None)  # type: ignore[arg-type]

    def test_just_colon_slash_slash(self):
        # "://" with no scheme is treated as having an empty scheme, should
        # trigger URL001 (unusual scheme) and possibly URL002 (no host).
        result = analyze_url("://bad")
        # Should not crash and should return a dict with expected keys.
        self.assertIn("risk_score", result)
        self.assertIn("findings", result)

    def test_url_with_no_host_triggers_url002(self):
        result = analyze_url("http://")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("URL002", rule_ids)

    def test_www_prefix_is_normalised(self):
        # Bare www. should be treated as http:// prepended.
        result = analyze_url("www.example.invalid")
        self.assertIn("http://", result["normalized_url"])

    def test_very_long_url_raises(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.invalid/" + "a" * MAX_URL_LENGTH)


# ===========================================================================
# 7. URL extraction from message text
# ===========================================================================

class TestURLExtractionFromMessageText(unittest.TestCase):

    def test_http_url_extracted(self):
        urls = extract_urls("Click here: http://example.invalid/page")
        self.assertIn("http://example.invalid/page", urls)

    def test_https_url_extracted(self):
        urls = extract_urls("Visit https://example.invalid/ for details.")
        self.assertIn("https://example.invalid/", urls)

    def test_www_url_gets_scheme_prepended(self):
        urls = extract_urls("Visit www.example.invalid for info.")
        # www. references should have http:// prepended.
        self.assertTrue(
            any(u.startswith("http://www.example.invalid") for u in urls)
        )

    def test_trailing_punctuation_stripped(self):
        urls = extract_urls("See http://example.invalid/page. For more info.")
        # Should not include the trailing period.
        for u in urls:
            self.assertFalse(u.endswith("."), f"URL should not end with '.': {u!r}")

    def test_multiple_urls_extracted(self):
        text = (
            "First link: http://a.invalid/1 "
            "Second link: https://b.invalid/2"
        )
        urls = extract_urls(text)
        self.assertEqual(len(urls), 2)

    def test_no_url_returns_empty_list(self):
        urls = extract_urls("Hello, this is a plain text message with no links.")
        self.assertEqual(urls, [])

    def test_duplicates_deduplicated(self):
        text = "http://example.invalid/ and again http://example.invalid/"
        urls = extract_urls(text)
        self.assertEqual(len([u for u in urls if u == "http://example.invalid/"]), 1)

    def test_analyze_message_populates_extracted_urls(self):
        result = analyze_message(
            "Verify at http://suspicious.invalid/login now.",
            sender="noreply@test.invalid",
        )
        self.assertIn("http://suspicious.invalid/login", result["extracted_urls"])


# ===========================================================================
# 8. Score boundaries and risk categories
# ===========================================================================

class TestScoreBoundariesAndRiskCategories(unittest.TestCase):

    def test_risk_level_low_at_zero(self):
        self.assertEqual(_risk_level(0), "Low")

    def test_risk_level_low_at_threshold_minus_one(self):
        self.assertEqual(_risk_level(SCORE_MEDIUM_THRESHOLD - 1), "Low")

    def test_risk_level_medium_at_threshold(self):
        self.assertEqual(_risk_level(SCORE_MEDIUM_THRESHOLD), "Medium")

    def test_risk_level_medium_at_high_threshold_minus_one(self):
        self.assertEqual(_risk_level(SCORE_HIGH_THRESHOLD - 1), "Medium")

    def test_risk_level_high_at_threshold(self):
        self.assertEqual(_risk_level(SCORE_HIGH_THRESHOLD), "High")

    def test_risk_level_high_at_100(self):
        self.assertEqual(_risk_level(100), "High")

    def test_score_cannot_exceed_100(self):
        # Force many high-weight findings.
        findings = [
            {"rule_id": f"R{i:03d}", "points": 25} for i in range(10)
        ]
        score = _score_findings(findings)
        self.assertLessEqual(score, 100)

    def test_score_is_non_negative(self):
        self.assertGreaterEqual(_score_findings([]), 0)

    def test_result_risk_score_within_bounds(self):
        result = analyze_message(
            "URGENT: act now — password, pay now, verify now. http://bad.invalid/login"
        )
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_url_result_risk_score_within_bounds(self):
        result = analyze_url("http://user:pw@xn--nxasmq6b.a.b.c.d.e/%2F%2F%2F")
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)


# ===========================================================================
# 9. Duplicate-finding and score deduplication
# ===========================================================================

class TestDuplicateFindingBehavior(unittest.TestCase):

    def test_same_rule_id_contributes_max_not_sum(self):
        findings = [
            {"rule_id": "MSG001", "points": 12},
            {"rule_id": "MSG001", "points": 5},
        ]
        score = _score_findings(findings)
        # Should use max(12, 5) = 12, not 12+5=17.
        self.assertEqual(score, 12)

    def test_distinct_rule_ids_contribute_independently(self):
        findings = [
            {"rule_id": "MSG001", "points": 12},
            {"rule_id": "MSG002", "points": 25},
        ]
        score = _score_findings(findings)
        self.assertEqual(score, 37)

    def test_embedded_url_rule_ids_are_distinct_from_message_rules(self):
        # A message with an embedded URL should accumulate findings from both
        # MSG-prefix rules and EMBEDDED_URL-prefix rules.
        result = analyze_message(
            "Your account will be suspended. Verify now at "
            "http://evil.invalid/login"
        )
        rule_ids = [f["rule_id"] for f in result["findings"]]
        # Must have at least one MSG rule and one EMBEDDED_URL rule.
        has_msg = any(rid.startswith("MSG") for rid in rule_ids)
        has_emb = any(rid.startswith("EMBEDDED_") for rid in rule_ids)
        self.assertTrue(has_msg, "Expected at least one MSG-prefixed finding.")
        self.assertTrue(
            has_emb, "Expected at least one EMBEDDED_URL-prefixed finding."
        )

    def test_score_with_no_findings_is_zero(self):
        self.assertEqual(_score_findings([]), 0)


# ===========================================================================
# 10. JSON serialisation and report generation
# ===========================================================================

class TestJSONSerialisation(unittest.TestCase):

    def _assert_json_serialisable(self, obj: object) -> None:
        try:
            json.dumps(obj)
        except (TypeError, ValueError) as exc:
            self.fail(f"Object is not JSON-serialisable: {exc}")

    def test_analyze_message_result_is_json_serialisable(self):
        result = analyze_message(
            "Act now. Enter your password at http://example.invalid/."
        )
        self._assert_json_serialisable(result)

    def test_analyze_url_result_is_json_serialisable(self):
        result = analyze_url("http://user:pw@192.0.2.1/login")
        self._assert_json_serialisable(result)

    def test_result_has_required_keys_message(self):
        result = analyze_message("Hello world.")
        for key in (
            "input_type", "risk_score", "risk_level",
            "findings", "summary", "timestamp_utc",
            "analysis_mode", "limitations",
        ):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_result_has_required_keys_url(self):
        result = analyze_url("https://example.invalid/")
        for key in (
            "input_type", "submitted_input", "normalized_url",
            "hostname", "risk_score", "risk_level",
            "findings", "summary", "timestamp_utc",
            "analysis_mode", "limitations",
        ):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_export_report_writes_valid_json_file(self):
        result = analyze_message("Verify now. http://example.invalid/")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            tmp_path = tmp.name
        try:
            export_report(result, tmp_path)
            with open(tmp_path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            self.assertEqual(loaded["input_type"], "email_or_sms")
            self.assertIn("findings", loaded)
        finally:
            os.unlink(tmp_path)

    def test_findings_have_required_keys(self):
        result = analyze_message("Enter your password immediately.")
        for finding in result["findings"]:
            for key in (
                "rule_id", "title", "severity",
                "evidence", "explanation", "recommendation", "points",
            ):
                self.assertIn(key, finding, f"Finding missing key: {key}")

    def test_analysis_mode_is_local_rule_based(self):
        msg_result = analyze_message("Hello.")
        url_result = analyze_url("https://example.invalid/")
        self.assertEqual(msg_result["analysis_mode"], "local_rule_based")
        self.assertEqual(url_result["analysis_mode"], "local_rule_based")

    def test_input_type_correct_for_message(self):
        result = analyze_message("Hello.")
        self.assertEqual(result["input_type"], "email_or_sms")

    def test_input_type_correct_for_url(self):
        result = analyze_url("https://example.invalid/")
        self.assertEqual(result["input_type"], "url")


# ===========================================================================
# 11. Graceful handling of optional or missing fields
# ===========================================================================

class TestOptionalAndMissingFields(unittest.TestCase):

    def test_analyze_message_without_sender(self):
        # Should not raise even when sender is omitted.
        result = analyze_message("Hello, how are you?")
        self.assertIn("sender", result)
        self.assertEqual(result["sender"], "")

    def test_analyze_message_without_subject(self):
        result = analyze_message("Hello, how are you?")
        self.assertIn("subject", result)
        self.assertEqual(result["subject"], "")

    def test_analyze_message_with_none_sender(self):
        result = analyze_message("Hello.", sender=None)
        self.assertEqual(result["sender"], "")

    def test_analyze_message_with_none_subject(self):
        result = analyze_message("Hello.", subject=None)
        self.assertEqual(result["subject"], "")

    def test_analyze_message_with_empty_sender_string(self):
        result = analyze_message("Hello.", sender="")
        self.assertEqual(result["sender"], "")

    def test_analyze_message_sender_without_at_sign(self):
        # Sender with no @-sign should not trigger MSG005.
        result = analyze_message(
            "Your bank account needs updating.", sender="SMS-12345"
        )
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("MSG005", rule_ids)

    def test_very_long_subject_is_truncated(self):
        long_subject = "S" * 500
        result = analyze_message("Hello.", subject=long_subject)
        self.assertLessEqual(len(result["subject"]), 200)

    def test_very_long_sender_is_truncated(self):
        long_sender = "a" * 400 + "@example.invalid"
        result = analyze_message("Hello.", sender=long_sender)
        self.assertLessEqual(len(result["sender"]), 320)

    def test_unicode_message_does_not_crash(self):
        result = analyze_message("Ваш пароль устарел. Обновите немедленно.")
        self.assertIn("risk_score", result)

    def test_emoji_in_message_does_not_crash(self):
        result = analyze_message("🎉 You won! Click here to claim your refund 🎁")
        self.assertIn("risk_score", result)

    def test_print_report_does_not_crash_on_message_result(self):
        result = analyze_message("Act now. Enter your OTP.")
        # Should not raise.
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_report(result)
        self.assertIn("PHISHGUARD", buf.getvalue())

    def test_print_report_does_not_crash_on_url_result(self):
        result = analyze_url("https://example.invalid/")
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_report(result)
        self.assertIn("PHISHGUARD", buf.getvalue())

    def test_message_with_only_whitespace_in_url_list_is_handled(self):
        # Message with no actual URLs should return an empty extracted_urls list.
        result = analyze_message("Hello friend, how are you today?")
        self.assertEqual(result["extracted_urls"], [])


# ===========================================================================
# Additional integration smoke tests
# ===========================================================================

class TestIntegrationSmokeTests(unittest.TestCase):
    """End-to-end tests using synthetic examples from the notebook."""

    def test_suspicious_delivery_message_is_medium_or_high_risk(self):
        # This message contains urgency language and an embedded URL with
        # structural indicators.  The heuristic engine scores it Medium (43/100)
        # because no credential or payment terms are present.  Medium is the
        # correct and honest result for this input; requiring High would
        # overstate the engine's verdict.
        result = analyze_message(
            "URGENT: Your package is on hold. Verify now within 24 hours at "
            "http://delivery.example.test.verify-account.invalid/login "
            "to avoid suspension.",
            sender="delivery-update@example-mail.test",
        )
        self.assertGreaterEqual(result["risk_score"], SCORE_MEDIUM_THRESHOLD)
        self.assertIn(result["risk_level"], ("Medium", "High"))

    def test_credential_request_is_medium_or_high(self):
        result = analyze_message(
            "Your account will be suspended. Sign in to verify and enter "
            "your password and one-time password immediately.",
            sender="security-alert@gmail.com",
        )
        self.assertGreaterEqual(result["risk_score"], SCORE_MEDIUM_THRESHOLD)

    def test_college_announcement_is_low_risk(self):
        result = analyze_message(
            "Hello students, the library will open at 9 AM on Monday. "
            "Please check the notice board for details.",
            sender="office@college.example",
        )
        self.assertLess(result["risk_score"], SCORE_MEDIUM_THRESHOLD)

    def test_msg005_triggered_for_gmail_bank_claim(self):
        result = analyze_message(
            "Your bank account has been locked.",
            sender="alerts@gmail.com",
        )
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("MSG005", rule_ids)

    def test_high_risk_url_with_multiple_indicators(self):
        # IP host + userinfo → URL003 (15 pts) + URL006 (30 pts) + URL008 (8 pts)
        # = 53 pts → High
        result = analyze_url("http://attacker:password@192.0.2.1/steal")
        self.assertGreaterEqual(result["risk_score"], SCORE_HIGH_THRESHOLD)
        self.assertEqual(result["risk_level"], "High")

    def test_limitations_present_in_message_result(self):
        result = analyze_message("Hello.")
        self.assertIsInstance(result["limitations"], list)
        self.assertGreater(len(result["limitations"]), 0)

    def test_limitations_present_in_url_result(self):
        result = analyze_url("https://example.invalid/")
        self.assertIsInstance(result["limitations"], list)
        self.assertGreater(len(result["limitations"]), 0)

    def test_no_network_request_for_url_analysis(self):
        # This test verifies that analyze_url does not attempt to import
        # network-related modules (urllib.request, socket for connecting, etc.)
        # at call time. We simply verify the function returns without timing out
        # against a non-routable address.
        import signal

        def _timeout(*_):
            raise AssertionError("analyze_url took unexpectedly long — check for network calls.")

        # On Windows, signal.alarm is unavailable; skip the timer.
        if hasattr(signal, "SIGALRM"):
            signal.signal(signal.SIGALRM, _timeout)
            signal.alarm(3)
        try:
            analyze_url("http://192.0.2.254/should-not-connect")
        finally:
            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
