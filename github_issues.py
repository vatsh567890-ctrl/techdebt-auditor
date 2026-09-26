"""
github_issues.py
----------------
Creates GitHub Issues for the top-N highest-risk backlog items via the
GitHub REST API.  Uses only stdlib — no extra dependencies required.
"""

import json
import urllib.error
import urllib.request
from typing import Any


def _repo_path(repo_url: str) -> str:
    """Extract 'owner/repo' from a GitHub URL."""
    # Handle trailing slashes and optional .git suffix
    path = repo_url.rstrip("/").removesuffix(".git")
    # Works for https://github.com/owner/repo
    parts = path.split("github.com/", 1)
    if len(parts) != 2 or "/" not in parts[1]:
        raise ValueError(f"Could not parse owner/repo from URL: {repo_url!r}")
    return parts[1]


def _build_body(item: dict[str, Any]) -> str:
    findings = item.get("risky_findings") or []
    findings_md = (
        "\n".join(f"- {r}" for r in findings)
        if findings
        else "_No specific risky pattern — flagged for general complexity / staleness._"
    )
    has_test = "Yes ✅" if item.get("has_test") else "No ❌"
    return (
        f"## Tech Debt / Security Finding\n\n"
        f"| Field | Value |\n"
        f"|---|---|\n"
        f"| **File** | `{item['file']}` |\n"
        f"| **Risk score** | {item['risk_score']} |\n"
        f"| **Effort estimate** | {item.get('effort_estimate', 'N/A')} |\n"
        f"| **Lines of code** | {item.get('line_count', 'N/A'):,} |\n"
        f"| **Days since last change** | {item.get('staleness_days', 'N/A')} |\n"
        f"| **Has test file** | {has_test} |\n\n"
        f"### Why this is flagged\n\n{findings_md}\n\n"
        f"---\n_Auto-created by Tech Debt & Security Auditor._"
    )


def create_issues(
    repo_url: str,
    token: str,
    items: list[dict[str, Any]],
    top_n: int = 5,
) -> list[dict[str, Any]]:
    """
    Create GitHub Issues for the top ``top_n`` items (already sorted
    highest-risk first).

    Returns a list of result dicts, one per item:
      {"file": str, "status": "created" | "error", "issue_url": str | None, "error": str | None}
    """
    repo_path = _repo_path(repo_url)
    api_url = f"https://api.github.com/repos/{repo_path}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }

    results = []
    for item in items[:top_n]:
        score = item["risk_score"]
        if score >= 70:
            risk_label = "HIGH"
        elif score >= 40:
            risk_label = "MEDIUM"
        else:
            risk_label = "LOW"

        payload = json.dumps(
            {
                "title": f"[TechDebt/{risk_label}] {item['file']} (score: {score})",
                "body": _build_body(item),
                "labels": ["tech-debt"],
            }
        ).encode()

        req = urllib.request.Request(api_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                results.append(
                    {"file": item["file"], "status": "created", "issue_url": data["html_url"], "error": None}
                )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            try:
                msg = json.loads(body).get("message", body)
            except Exception:
                msg = body
            results.append({"file": item["file"], "status": "error", "issue_url": None, "error": f"HTTP {exc.code}: {msg}"})
        except Exception as exc:
            results.append({"file": item["file"], "status": "error", "issue_url": None, "error": str(exc)})

    return results
