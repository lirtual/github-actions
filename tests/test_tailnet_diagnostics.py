"""Read-only Tailnet failure telemetry must never expose network or OIDC data."""
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/tailnet-diagnostics.py"
spec = importlib.util.spec_from_file_location("tailnet_diagnostics", SCRIPT)
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def capture(callback):
    output = io.StringIO()
    with redirect_stdout(output):
        callback()
    return output.getvalue()


class TailnetDiagnosticsTests(unittest.TestCase):
    def test_allowed_status_only(self):
        data = (b'{"BackendState":"NeedsLogin","AuthURL":"https://secret",'
                b'"TailscaleIPs":["100.64.2.5"],"Health":["jwt_secret"]}')
        with patch.object(diag.subprocess, "run",
                          return_value=subprocess.CompletedProcess(
                              (), 0, data, b"SECRET_ERROR")):
            output = capture(diag.report_state)
        self.assertEqual(output, "tailnet_status=NeedsLogin\n"
                         "tailnet_ips_present=true\n"
                         "tailnet_health_present=true\n")
        self.assertNotIn("secret", output)
        self.assertNotIn("100.", output)

    def test_unexpected_status_is_never_reflected(self):
        with patch.object(diag.subprocess, "run",
                          return_value=subprocess.CompletedProcess(
                              (), 0, b'{"BackendState":"my_oauth_token"}', b"")):
            output = capture(diag.report_state)
        self.assertEqual(output, "tailnet_status=other\n"
                         "tailnet_ips_present=false\n"
                         "tailnet_health_present=false\n")

    def test_status_timeout_is_bounded_and_silent(self):
        with patch.object(diag.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("tailscale", 4)):
            self.assertEqual(capture(diag.report_state),
                             "tailnet_status=unavailable\n")

    def test_https_failure_redacts_exception(self):
        with patch.object(diag.urllib.request, "build_opener") as factory:
            factory.return_value.open.side_effect = diag.urllib.error.URLError(
                "authorization token private-address"
            )
            self.assertEqual(capture(lambda: diag.probe_https("api.tailscale.com")),
                             "https_api=unavailable\n")

    def test_http_error_still_means_https_reachable(self):
        error = diag.urllib.error.HTTPError(
            "https://api.tailscale.com/", 403, "sensitive", {}, None
        )
        with patch.object(diag.urllib.request, "build_opener") as factory:
            factory.return_value.open.side_effect = error
            self.assertEqual(capture(lambda: diag.probe_https("api.tailscale.com")),
                             "https_api=reachable\n")


if __name__ == "__main__":
    unittest.main()