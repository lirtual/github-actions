"""Bounded post-failure Tailnet diagnostics with no raw credentials or node data."""
import json
import subprocess
import urllib.error
import urllib.request

STATES = frozenset(("Running", "NeedsLogin", "Starting", "Stopped",
                    "NoState", "NeedsMachineAuth"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def report_state():
    try:
        result = subprocess.run(
            ("tailscale", "status", "--json"),
            capture_output=True, timeout=4, check=False,
        )
        if result.returncode != 0:
            print("tailnet_status=unavailable")
            return
        status = json.loads(result.stdout)
        state = status.get("BackendState")
        print("tailnet_status=" + (state if state in STATES else "other"))
        print("tailnet_ips_present=" +
              str(bool(status.get("TailscaleIPs"))).lower())
        print("tailnet_health_present=" +
              str(bool(status.get("Health"))).lower())
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        print("tailnet_status=unavailable")


def probe_https(host):
    # No bodies, headers, IP addresses, redirects or error text reach the logs.
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(
            urllib.request.Request("https://" + host + "/", method="HEAD"),
            timeout=5,
        ):
            pass
        result = "reachable"
    except urllib.error.HTTPError:
        # Any HTTP response (including 4xx/3xx) proves HTTPS reached this host.
        result = "reachable"
    except (OSError, ValueError):
        result = "unavailable"
    print("https_" + host.split(".")[0] + "=" + result)


def main():
    report_state()
    for host in ("api.tailscale.com", "controlplane.tailscale.com"):
        probe_https(host)


if __name__ == "__main__":
    main()