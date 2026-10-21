"""Security Log Analyzer MCP server.

A small Model Context Protocol server that reviews sample login activity.
The records below are fake and are only used for this assignment.
"""

from mcp.server.fastmcp import FastMCP

FAILED_LOGIN_THRESHOLD = 3

mcp = FastMCP("Security Log Analyzer")

# Fake login activity. Each record has a username, IP address, timestamp,
# and whether the attempt succeeded or failed.
LOGIN_LOGS: list[dict[str, str]] = [
    {
        "username": "alice",
        "ip_address": "192.168.1.10",
        "timestamp": "2026-10-21T08:01:00",
        "status": "success",
    },
    {
        "username": "bob",
        "ip_address": "10.0.0.25",
        "timestamp": "2026-10-21T08:05:12",
        "status": "failed",
    },
    {
        "username": "bob",
        "ip_address": "10.0.0.25",
        "timestamp": "2026-10-21T08:05:40",
        "status": "failed",
    },
    {
        "username": "bob",
        "ip_address": "10.0.0.25",
        "timestamp": "2026-10-21T08:06:05",
        "status": "failed",
    },
    {
        "username": "carol",
        "ip_address": "203.0.113.44",
        "timestamp": "2026-10-21T09:12:03",
        "status": "failed",
    },
    {
        "username": "dave",
        "ip_address": "203.0.113.44",
        "timestamp": "2026-10-21T09:12:18",
        "status": "failed",
    },
    {
        "username": "alice",
        "ip_address": "203.0.113.44",
        "timestamp": "2026-10-21T09:13:01",
        "status": "failed",
    },
    {
        "username": "eve",
        "ip_address": "198.51.100.7",
        "timestamp": "2026-10-21T10:22:45",
        "status": "success",
    },
    {
        "username": "frank",
        "ip_address": "192.168.1.55",
        "timestamp": "2026-10-21T11:03:09",
        "status": "failed",
    },
    {
        "username": "frank",
        "ip_address": "192.168.1.55",
        "timestamp": "2026-10-21T11:04:11",
        "status": "success",
    },
    {
        "username": "grace",
        "ip_address": "203.0.113.44",
        "timestamp": "2026-10-21T11:40:00",
        "status": "failed",
    },
]


@mcp.tool()
def get_login_logs() -> list[dict[str, str]]:
    """Return the sample login activity logs.

    Each record includes a username, IP address, timestamp, and a status
    of success or failed.
    """
    return LOGIN_LOGS


@mcp.tool()
def count_failed_logins() -> int:
    """Count how many login attempts in the sample logs failed."""
    failed_count = 0
    for record in LOGIN_LOGS:
        if record["status"] == "failed":
            failed_count += 1
    return failed_count


@mcp.tool()
def find_suspicious_ips() -> list[dict[str, str | int]]:
    """Find IP addresses with 3 or more failed login attempts.

    Returns each suspicious address and how many failures it has.
    """
    failure_counts: dict[str, int] = {}
    for record in LOGIN_LOGS:
        if record["status"] != "failed":
            continue
        ip_address = record["ip_address"]
        failure_counts[ip_address] = failure_counts.get(ip_address, 0) + 1
    suspicious_ips: list[dict[str, str | int]] = []
    for ip_address, failed_count in failure_counts.items():
        if failed_count >= FAILED_LOGIN_THRESHOLD:
            suspicious_ips.append(
                {"ip_address": ip_address, "failed_count": failed_count}
            )
    return suspicious_ips


if __name__ == "__main__":
    mcp.run(transport="stdio")
