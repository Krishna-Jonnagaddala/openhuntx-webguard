"""Tests for bounded passive HTML security analysis."""

from __future__ import annotations

import unittest

from webguard_contracts import Confidence, Severity
from webguard_scanner import (
    HTML_CHECKS,
    HtmlAnalysisError,
    MAXIMUM_HTML_ANALYSIS_BYTES,
    MAXIMUM_HTML_ELEMENTS,
    SafeHttpResponse,
    ValidatedTarget,
    analyze_html_security,
)


def target(
    *,
    scheme: str = "https",
    url: str = "https://example.com/account/login",
    hostname: str = "example.com",
    port: int = 443,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_addresses=("93.184.216.34",),
    )


def response(
    body: str | bytes,
    *,
    content_type: str | None = "text/html; charset=utf-8",
) -> SafeHttpResponse:
    headers = (
        (("Content-Type", content_type),)
        if content_type is not None
        else ()
    )
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=headers,
        body=(body.encode("utf-8") if isinstance(body, str) else body),
        connected_address="93.184.216.34",
        elapsed_milliseconds=10,
    )


def rules(findings) -> set[str]:
    return {
        finding.identity.rule_id
        for finding in findings
    }


class HtmlAnalyzerTests(unittest.TestCase):
    def test_check_registry_is_canonical(self) -> None:
        self.assertEqual(HTML_CHECKS, tuple(sorted(HTML_CHECKS)))
        self.assertEqual(len(HTML_CHECKS), 10)

    def test_non_html_response_is_not_parsed(self) -> None:
        findings = analyze_html_security(
            target(),
            response('{"error":"Traceback (most recent call last)"}', content_type="application/json"),
        )
        self.assertEqual(findings, ())

    def test_html_is_sniffed_when_content_type_is_missing(self) -> None:
        findings = analyze_html_security(
            target(
                scheme="http",
                url="http://example.com/login",
                port=80,
            ),
            response(
                "<html><form><input type='password'></form></html>",
                content_type=None,
            ),
        )
        self.assertIn(
            "web.html.password_transport.insecure",
            rules(findings),
        )

    def test_xhtml_content_type_is_supported(self) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<html xmlns='http://www.w3.org/1999/xhtml'></html>",
                content_type="application/xhtml+xml",
            ),
        )
        self.assertEqual(findings, ())

    def test_body_limit_is_enforced(self) -> None:
        with self.assertRaises(HtmlAnalysisError) as context:
            analyze_html_security(
                target(),
                response(b"<" + b"a" * MAXIMUM_HTML_ANALYSIS_BYTES),
            )
        self.assertEqual(
            context.exception.code,
            "html_body_limit_exceeded",
        )

    def test_element_limit_is_enforced(self) -> None:
        document = "<html>" + "<span></span>" * MAXIMUM_HTML_ELEMENTS + "</html>"
        with self.assertRaises(HtmlAnalysisError) as context:
            analyze_html_security(target(), response(document))
        self.assertEqual(
            context.exception.code,
            "html_element_limit_exceeded",
        )

    def test_rejects_inconsistent_validated_target(self) -> None:
        inconsistent = target(hostname="other.example")
        with self.assertRaises(HtmlAnalysisError) as context:
            analyze_html_security(inconsistent, response("<html></html>"))
        self.assertEqual(
            context.exception.code,
            "validated_target_mismatch",
        )

    def test_http_password_form_reports_transport_and_get_method(self) -> None:
        findings = analyze_html_security(
            target(
                scheme="http",
                url="http://example.com/login",
                port=80,
            ),
            response("<form><input type='password' value='do-not-store'></form>"),
        )
        self.assertEqual(
            rules(findings),
            {
                "web.html.password_method.get",
                "web.html.password_transport.insecure",
            },
        )
        self.assertNotIn("do-not-store", repr(findings))

    def test_https_post_password_form_is_not_reported(self) -> None:
        # A recognized CSRF token field is included so this test stays
        # scoped to the password-transport/method checks; the CSRF check
        # itself is covered by its own dedicated tests below.
        findings = analyze_html_security(
            target(),
            response(
                "<form method='post'>"
                "<input type='password'>"
                "<input type='hidden' name='_token' value='abc123'>"
                "</form>"
            ),
        )
        self.assertEqual(findings, ())

    def test_https_get_password_form_reports_only_get_method(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<form method='GET'><input type='PASSWORD'></form>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.password_method.get"},
        )

    def test_password_input_outside_form_is_not_treated_as_form(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<input type='password'>"),
        )
        self.assertEqual(findings, ())

    def test_multiple_password_forms_have_unique_identity_parameters(self) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<form><input type='password'></form>"
                "<form><input type='password'></form>"
            ),
        )
        parameters = {
            finding.identity.parameter
            for finding in findings
            if finding.identity.rule_id == "web.html.password_method.get"
        }
        self.assertEqual(parameters, {"form:1", "form:2"})

    def test_cross_origin_form_action_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<form action='https://collector.example/submit'></form>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.form_action.cross_origin"},
        )
        self.assertNotIn("collector.example/submit", repr(findings))

    def test_relative_form_action_is_same_origin(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<form action='/submit'></form>"),
        )
        self.assertEqual(findings, ())

    def test_explicit_default_port_is_same_origin(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<form action='https://example.com:443/submit'></form>"),
        )
        self.assertEqual(findings, ())

    def test_protocol_relative_cross_origin_form_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<form action='//forms.example.net/submit'></form>"),
        )
        self.assertIn(
            "web.html.form_action.cross_origin",
            rules(findings),
        )

    def test_post_form_with_no_token_field_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<form method='POST' action='/update'><input name='email'></form>"),
        )
        self.assertEqual(rules(findings), {"web.html.csrf_token.absent"})
        finding = findings[0]
        self.assertIs(finding.severity, Severity.MEDIUM)
        self.assertIs(finding.confidence, Confidence.LOW)
        self.assertEqual(
            [i.value for i in finding.identifiers], ["CWE-352"],
        )

    def test_get_form_is_never_checked_for_a_csrf_token(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<form method='GET' action='/search'><input name='q'></form>"),
        )
        self.assertEqual(findings, ())

    def test_substring_token_name_suppresses_the_finding(self) -> None:
        # Django's csrfmiddlewaretoken, matched via the substring pattern.
        findings = analyze_html_security(
            target(),
            response(
                "<form method='POST' action='/update'>"
                "<input type='hidden' name='csrfmiddlewaretoken' value='abc123'>"
                "</form>"
            ),
        )
        self.assertEqual(findings, ())

    def test_exact_token_name_suppresses_the_finding(self) -> None:
        # Laravel/Symfony's bare "_token", matched via the exact-name set,
        # never the substring pattern (it contains none of those words).
        findings = analyze_html_security(
            target(),
            response(
                "<form method='POST' action='/update'>"
                "<input type='hidden' name='_token' value='abc123'>"
                "</form>"
            ),
        )
        self.assertEqual(findings, ())

    def test_wordpress_nonce_field_suppresses_the_finding(self) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<form method='POST' action='/comment'>"
                "<input type='hidden' name='_wpnonce' value='xyz'>"
                "</form>"
            ),
        )
        self.assertEqual(findings, ())

    def test_unrelated_token_suffixed_field_is_not_mistaken_for_csrf(self) -> None:
        # "reset_token"/"api_token" are real, common non-CSRF field names
        # that share a suffix with "_token": the exact-match rule (never
        # a substring match) exists specifically so these do not suppress
        # the finding, matching this project's own reasoning for keeping
        # the check narrow rather than broad.
        for field_name in ("reset_token", "api_token", "invite_token"):
            with self.subTest(field_name=field_name):
                findings = analyze_html_security(
                    target(),
                    response(
                        "<form method='POST' action='/update'>"
                        f"<input type='hidden' name='{field_name}' value='abc'>"
                        "</form>"
                    ),
                )
                self.assertEqual(rules(findings), {"web.html.csrf_token.absent"})

    def test_empty_token_value_does_not_suppress_the_finding(self) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<form method='POST' action='/update'>"
                "<input type='hidden' name='csrf_token' value=''>"
                "</form>"
            ),
        )
        self.assertEqual(rules(findings), {"web.html.csrf_token.absent"})

    def test_unrendered_template_placeholder_value_does_not_suppress_the_finding(
        self,
    ) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<form method='POST' action='/update'>"
                "<input type='hidden' name='csrf_token' value='{{ csrf_token }}'>"
                "</form>"
            ),
        )
        self.assertEqual(rules(findings), {"web.html.csrf_token.absent"})

    def test_visible_input_with_a_matching_name_does_not_count(self) -> None:
        # Only a hidden field counts as a plausible anti-CSRF token; a
        # visible text input happening to share a matching name is not
        # evidence of protection.
        findings = analyze_html_security(
            target(),
            response(
                "<form method='POST' action='/update'>"
                "<input type='text' name='csrf_token' value='abc123'>"
                "</form>"
            ),
        )
        self.assertEqual(rules(findings), {"web.html.csrf_token.absent"})

    def test_csrf_finding_evidence_never_contains_field_names_or_values(
        self,
    ) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<form method='POST' action='/update'>"
                "<input name='super_secret_field_name' value='super-secret-value'>"
                "</form>"
            ),
        )
        evidence_text = findings[0].evidence[0].summary
        self.assertNotIn("super_secret_field_name", evidence_text)
        self.assertNotIn("super-secret-value", evidence_text)

    def test_multiple_forms_are_classified_independently_for_csrf(self) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<form method='POST' action='/a'>"
                "<input type='hidden' name='_token' value='abc'>"
                "</form>"
                "<form method='POST' action='/b'></form>"
            ),
        )
        csrf_findings = [
            f for f in findings if f.identity.rule_id == "web.html.csrf_token.absent"
        ]
        self.assertEqual(len(csrf_findings), 1)
        self.assertEqual(csrf_findings[0].identity.parameter, "form:2")

    def test_http_script_on_https_page_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<script src='http://cdn.example/app.js'></script>"),
        )
        finding = findings[0]
        self.assertEqual(
            finding.identity.rule_id,
            "web.html.insecure_subresource.script",
        )
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertNotIn("cdn.example/app.js", repr(finding))

    def test_http_stylesheet_on_https_page_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<link rel='stylesheet' href='http://cdn.example/app.css'>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.insecure_subresource.stylesheet"},
        )

    def test_preloaded_script_over_http_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<link rel='preload' as='script' href='http://cdn.example/app.js'>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.insecure_subresource.script"},
        )

    def test_relative_script_on_https_page_is_not_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<script src='/assets/app.js'></script>"),
        )
        self.assertEqual(findings, ())

    def test_http_subresource_on_http_page_is_not_mixed_content(self) -> None:
        findings = analyze_html_security(
            target(
                scheme="http",
                url="http://example.com/",
                port=80,
            ),
            response("<script src='http://cdn.example/app.js'></script>"),
        )
        self.assertEqual(findings, ())

    def test_http_iframe_on_https_page_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<iframe src='http://legacy.example/frame'></iframe>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.mixed_active_content.iframe"},
        )

    def test_http_embed_and_object_are_reported_separately(self) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<embed src='http://legacy.example/a'>"
                "<object data='http://legacy.example/b'></object>"
            ),
        )
        self.assertEqual(
            rules(findings),
            {
                "web.html.mixed_active_content.embed",
                "web.html.mixed_active_content.object",
            },
        )

    def test_same_origin_meta_refresh_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<meta http-equiv='refresh' content='5; url=/next'>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.meta_refresh.redirect"},
        )

    def test_external_meta_refresh_is_medium_severity(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<meta http-equiv='refresh' content='0;URL=https://other.example/'>"),
        )
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.html.meta_refresh.external",
        )
        self.assertIs(findings[0].severity, Severity.MEDIUM)

    def test_https_to_http_meta_refresh_is_reported_as_insecure(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<meta http-equiv='refresh' content='0; url=http://example.com/'>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.meta_refresh.insecure"},
        )

    def test_meta_refresh_without_url_is_not_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<meta http-equiv='refresh' content='30'>"),
        )
        self.assertEqual(findings, ())

    def test_directory_listing_title_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<title>Index of /uploads</title>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.directory_listing.exposed"},
        )
        self.assertIs(findings[0].confidence, Confidence.HIGH)

    def test_directory_listing_body_markers_are_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<p>Parent Directory</p><p>Last modified</p><p>Size</p>"),
        )
        self.assertIn(
            "web.html.directory_listing.exposed",
            rules(findings),
        )

    def test_generic_index_text_is_not_directory_listing(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<title>Documentation index</title><p>Size guide</p>"),
        )
        self.assertEqual(findings, ())

    def test_python_traceback_is_reported_without_raw_trace(self) -> None:
        body = (
            "<pre>Traceback (most recent call last):\n"
            "File /srv/app.py, line 10, in handler\n"
            "ValueError: secret-value</pre>"
        )
        findings = analyze_html_security(target(), response(body))
        self.assertEqual(
            rules(findings),
            {"web.html.debug_exposure.stack_trace"},
        )
        self.assertNotIn("secret-value", repr(findings))

    def test_django_debug_page_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<h1>Django Version: 5.0</h1><p>Exception Type: ValueError</p>"),
        )
        self.assertIn(
            "web.html.debug_exposure.stack_trace",
            rules(findings),
        )

    def test_javascript_stack_trace_is_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<pre>TypeError: failed\n    at handler (/srv/app.js:10:2)</pre>"),
        )
        self.assertIn(
            "web.html.debug_exposure.stack_trace",
            rules(findings),
        )

    def test_generic_error_page_is_not_stack_trace(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<h1>Something went wrong</h1><p>Please try again.</p>"),
        )
        self.assertEqual(findings, ())

    def test_script_text_is_excluded_from_debug_detection(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<script>const x = 'Traceback (most recent call last) line 1';</script>"),
        )
        self.assertEqual(findings, ())

    def test_secret_comment_marker_is_reported_and_redacted(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<!-- api_key = super-sensitive-value -->"),
        )
        finding = findings[0]
        self.assertEqual(
            finding.identity.rule_id,
            "web.html.sensitive_comment.secret_marker",
        )
        self.assertNotIn("super-sensitive-value", repr(finding))
        self.assertIn("API key assignment", finding.evidence[0].summary)

    def test_development_comment_marker_is_informational(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<!-- TODO: remove localhost:3000 before release -->"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.sensitive_comment.development_marker"},
        )
        self.assertIs(findings[0].severity, Severity.INFORMATIONAL)

    def test_ordinary_comment_is_not_reported(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<!-- navigation starts here -->"),
        )
        self.assertEqual(findings, ())

    def test_malformed_html_is_tolerated(self) -> None:
        findings = analyze_html_security(
            target(),
            response("<html><form><input type=password><div>"),
        )
        self.assertEqual(
            rules(findings),
            {"web.html.password_method.get"},
        )

    def test_findings_are_deterministically_sorted(self) -> None:
        findings = analyze_html_security(
            target(),
            response(
                "<!-- TODO -->"
                "<form><input type='password'></form>"
                "<script src='http://cdn.example/a.js'></script>"
            ),
        )
        ordering = [
            (
                item.identity.rule_id,
                item.identity.parameter or "",
            )
            for item in findings
        ]
        self.assertEqual(ordering, sorted(ordering))


if __name__ == "__main__":
    unittest.main()
