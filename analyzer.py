"""
analyzer.py
-----------
The "brain" of the Technical Debt / Security Auditor.

This file does 4 things:
1. Clones (or reads) a target repository
2. Walks every code file and measures: staleness, size/complexity,
   whether tests exist, and whether risky code patterns appear
3. Combines those into a single 0-100 risk score per file
4. Returns a sorted "fix this first" backlog

You do not need to understand every line. Read the comments (the lines
starting with #) -- they explain what each part is for in plain English.
"""

import io
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# STEP 1: Which file types count as "code" we should scan
# ---------------------------------------------------------------------------
CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".c", ".cpp", ".cs"}

# Folders we should never bother scanning (dependencies, build output, etc.)
IGNORE_DIRS = {".git", "node_modules", "venv", "__pycache__", "dist", "build", ".next"}

# ---------------------------------------------------------------------------
# STEP 2: "Risky pattern" rules -- base set applied in every mode
# ---------------------------------------------------------------------------
RISKY_PATTERNS = [
    (r"\beval\(", "Uses eval() -- can execute arbitrary code, common security risk"),
    (r"\bexec\(", "Uses exec() -- can execute arbitrary code"),
    (r"os\.system\(", "Uses os.system() -- shell injection risk if input isn't sanitized"),
    (r"(?i)(password|secret|api_key|apikey)\s*=\s*[\"'][^\"']+[\"']", "Possible hardcoded credential/secret"),
    (r"(?i)select\s+\*\s+from.+\+", "Possible SQL injection (string-concatenated query)"),
    (r"\bpickle\.loads\(", "Uses pickle.loads() -- unsafe deserialization risk"),
    (r"#\s*(TODO|FIXME|HACK)", "Contains TODO/FIXME/HACK marker -- known unfinished/risky area"),
]
COMPILED_PATTERNS = [(re.compile(p), msg) for p, msg in RISKY_PATTERNS]

# ---------------------------------------------------------------------------
# STEP 2b: Compliance-specific extra patterns
#   Each entry: (regex, human message, set-of-applicable-modes)
#   "modes" is a frozenset of profile names that should run this check.
# ---------------------------------------------------------------------------
_COMPLIANCE_PATTERNS = [
    # ── HIPAA ────────────────────────────────────────────────────────────────
    # PHI field names stored or logged in plaintext
    (
        r"(?i)(ssn|social.?security|date.?of.?birth|dob|patient.?id|medical.?record"
        r"|diagnosis|prescription|insurance.?id|health.?plan)",
        "[HIPAA] Possible PHI field reference — verify data is encrypted at rest and in transit",
        frozenset({"hipaa"}),
    ),
    # Logging calls that might capture PHI
    (
        r"(?i)(log|print|console\.log|logger)\s*[\.\(].*(patient|phi|ssn|dob|diagnosis)",
        "[HIPAA] Possible PHI value passed to a logging call — audit trail must not expose PHI",
        frozenset({"hipaa"}),
    ),
    # Unencrypted HTTP endpoint (naive but useful signal)
    (
        r"http://(?!localhost|127\.0\.0\.1)",
        "[HIPAA] Plaintext HTTP URL — HIPAA requires encryption in transit (use HTTPS)",
        frozenset({"hipaa", "pci"}),
    ),

    # ── PCI-DSS ──────────────────────────────────────────────────────────────
    # Primary Account Number patterns (Luhn-range card numbers)
    (
        r"(?<!\d)(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
        r"|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11})",
        "[PCI-DSS] Possible hardcoded PAN (card number) — storing PANs in source violates PCI DSS Req 3",
        frozenset({"pci"}),
    ),
    # CVV / CVV2 field names
    (
        r"(?i)\b(cvv|cvv2|cvc|csc|card.?verification)\b",
        "[PCI-DSS] CVV/CVC field reference — must never be stored post-authorisation (PCI DSS Req 3.2)",
        frozenset({"pci"}),
    ),
    # Weak/banned crypto
    (
        r"(?i)\b(md5|sha1|des\b|3des|rc4)\b",
        "[PCI-DSS] Weak or banned cryptographic algorithm — PCI DSS Req 4/6 requires TLS 1.2+ and strong ciphers",
        frozenset({"hipaa", "pci"}),
    ),
    # Audit logging absence heuristic: files with auth/payment keywords but no log call
    (
        r"(?i)(charge|transaction|payment|authoris|authoriz)(?!.*\b(log|audit|record)\b)",
        "[PCI-DSS] Payment operation without apparent audit log call — PCI DSS Req 10 requires logging",
        frozenset({"pci"}),
    ),
]
_COMPILED_COMPLIANCE = [
    (re.compile(p), msg, modes) for p, msg, modes in _COMPLIANCE_PATTERNS
]

# ---------------------------------------------------------------------------
# STEP 3: Scoring profiles
#   Each profile defines the four component weights (must sum to 1.0) and a
#   per-finding score multiplier for compliance-tagged findings.
# ---------------------------------------------------------------------------
class ScoringProfile:
    """
    Immutable scoring configuration.  Pass one to compute_risk_score() to
    change how the four components are weighted and how many extra points a
    compliance finding adds to the pattern_score.
    """
    __slots__ = ("name", "label", "w_complexity", "w_staleness", "w_missing_test",
                 "w_patterns", "compliance_finding_pts")

    def __init__(
        self,
        name: str,
        label: str,
        w_complexity: float,
        w_staleness: float,
        w_missing_test: float,
        w_patterns: float,
        compliance_finding_pts: float,
    ):
        assert abs(w_complexity + w_staleness + w_missing_test + w_patterns - 1.0) < 1e-9, \
            "Weights must sum to 1.0"
        self.name = name
        self.label = label
        self.w_complexity = w_complexity
        self.w_staleness = w_staleness
        self.w_missing_test = w_missing_test
        self.w_patterns = w_patterns
        self.compliance_finding_pts = compliance_finding_pts


# Pre-built profiles ──────────────────────────────────────────────────────────
PROFILE_DEFAULT = ScoringProfile(
    name="default",
    label="Default",
    w_complexity=0.30,
    w_staleness=0.25,
    w_missing_test=0.25,
    w_patterns=0.20,
    compliance_finding_pts=0,          # compliance patterns not active
)

PROFILE_HIPAA = ScoringProfile(
    name="hipaa",
    label="HIPAA",
    # PHI exposure and missing tests dominate; raw complexity matters less
    w_complexity=0.15,
    w_staleness=0.15,
    w_missing_test=0.30,
    w_patterns=0.40,
    compliance_finding_pts=20,         # each HIPAA finding adds 20 pts to pattern sub-score
)

PROFILE_PCI = ScoringProfile(
    name="pci",
    label="PCI-DSS",
    # Risky patterns (card data, weak crypto) dominate; staleness still matters
    w_complexity=0.10,
    w_staleness=0.20,
    w_missing_test=0.25,
    w_patterns=0.45,
    compliance_finding_pts=25,         # each PCI finding adds 25 pts to pattern sub-score
)

PROFILES: dict[str, ScoringProfile] = {
    p.name: p for p in (PROFILE_DEFAULT, PROFILE_HIPAA, PROFILE_PCI)
}


def clone_repo(repo_url: str) -> str:
    """Clones a GitHub repo into a temp folder and returns the local path."""
    dest = tempfile.mkdtemp(prefix="repo_")
    subprocess.run(
        ["git", "clone", "--depth", "100", repo_url, dest],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def extract_zip(zip_bytes: bytes) -> str:
    """
    Extract a ZIP archive from raw bytes into a fresh temp directory.

    Returns the path to the extracted root.  If the ZIP contains a single
    top-level folder (the common case for GitHub-style download ZIPs) the
    returned path points directly to that folder so ``scan_backlog_iter``
    doesn't see a one-file-deep wrapper.
    """
    import zipfile

    dest = tempfile.mkdtemp(prefix="zip_repo_")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(dest)

    # Unwrap single top-level directory (e.g. "my-repo-main/")
    entries = [e for e in os.listdir(dest) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])):
        return os.path.join(dest, entries[0])
    return dest


def days_since_last_commit(repo_path: str, file_path: str) -> int:
    """How many days since this specific file was last changed."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "log", "-1", "--format=%ct", "--", file_path],
            capture_output=True,
            text=True,
            check=True,
        )
        timestamp_str = result.stdout.strip()
        if not timestamp_str:
            return 0  # no history found, treat as neutral
        last_commit_time = int(timestamp_str)
        return int((time.time() - last_commit_time) / 86400)
    except Exception:
        return 0


def has_matching_test(repo_path: str, file_rel_path: str) -> bool:
    """Very simple heuristic: does a test file with a similar name exist anywhere?"""
    stem = Path(file_rel_path).stem
    for root, _, files in os.walk(repo_path):
        for f in files:
            if stem in f and ("test" in f.lower()):
                return True
    return False


def scan_file(repo_path: str, rel_path: str, profile: ScoringProfile = PROFILE_DEFAULT) -> dict:
    """Reads one file and computes all its risk metrics."""
    full_path = os.path.join(repo_path, rel_path)
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return None

    lines = content.splitlines()
    line_count = len(lines)

    # crude "complexity": count how many lines are deeply indented
    deep_indent_lines = sum(1 for l in lines if l.startswith(" " * 12) or l.startswith("\t\t\t"))

    matched_reasons = []
    for pattern, message in COMPILED_PATTERNS:
        if pattern.search(content):
            matched_reasons.append(message)

    # Compliance-specific patterns — only run those applicable to this profile
    compliance_findings = []
    if profile.name != "default":
        for pattern, message, modes in _COMPILED_COMPLIANCE:
            if profile.name in modes and pattern.search(content):
                compliance_findings.append(message)

    staleness_days = days_since_last_commit(repo_path, rel_path)
    tested = has_matching_test(repo_path, rel_path)

    return {
        "file": rel_path,
        "line_count": line_count,
        "deep_indent_lines": deep_indent_lines,
        "staleness_days": staleness_days,
        "has_test": tested,
        "risky_findings": matched_reasons,
        "compliance_findings": compliance_findings,
    }


def compute_risk_score(metrics: dict, profile: ScoringProfile = PROFILE_DEFAULT) -> float:
    """
    Combines raw metrics into one 0-100 risk score using ``profile`` weights.

    ``metrics`` must include the standard keys produced by ``scan_file``.
    Compliance findings stored in ``metrics["compliance_findings"]`` receive
    a bonus of ``profile.compliance_finding_pts`` each on top of the base
    pattern sub-score (capped at 100 overall).
    """
    complexity_score = min(100, (metrics["line_count"] / 5) + (metrics["deep_indent_lines"] * 3))
    staleness_score = min(100, metrics["staleness_days"] / 3)
    missing_test_score = 0 if metrics["has_test"] else 100

    base_pattern_pts = len(metrics["risky_findings"]) * 35
    compliance_pts = len(metrics.get("compliance_findings", [])) * profile.compliance_finding_pts
    pattern_score = min(100, base_pattern_pts + compliance_pts)

    total = (
        profile.w_complexity    * complexity_score
        + profile.w_staleness   * staleness_score
        + profile.w_missing_test * missing_test_score
        + profile.w_patterns    * pattern_score
    )
    return round(total, 1)


def estimate_effort(metrics: dict, score: float) -> str:
    """Very simple effort heuristic -- swap this for an AI-generated estimate later."""
    if score >= 70 or metrics["line_count"] > 400:
        return "1+ day"
    elif score >= 40:
        return "Half a day"
    else:
        return "A few hours"


def _collect_code_files(repo_path: str) -> list[str]:
    """Return all relative paths of scannable code files in the repo."""
    paths = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for filename in files:
            if Path(filename).suffix in CODE_EXTENSIONS:
                paths.append(os.path.relpath(os.path.join(root, filename), repo_path))
    return paths


def scan_backlog_iter(repo_path: str, profile: ScoringProfile = PROFILE_DEFAULT):
    """
    Generator variant of build_backlog.

    Yields ``(item, current, total)`` tuples as each file is scanned so the
    caller can drive a progress bar.  The final sorted backlog is NOT returned
    here — collect the items yourself and sort by ``risk_score`` descending.
    Pass a ``ScoringProfile`` to apply compliance-aware scoring.
    """
    rel_paths = _collect_code_files(repo_path)
    total = len(rel_paths)
    for idx, rel_path in enumerate(rel_paths, start=1):
        metrics = scan_file(repo_path, rel_path, profile)
        if metrics is None:
            yield None, idx, total
            continue
        score = compute_risk_score(metrics, profile)
        item = {**metrics, "risk_score": score, "effort_estimate": estimate_effort(metrics, score),
                "scoring_profile": profile.name}
        yield item, idx, total


def build_backlog(repo_path: str, profile: ScoringProfile = PROFILE_DEFAULT) -> list:
    """Walks the whole repo and returns a sorted list of risk-scored files."""
    backlog = [
        item
        for item, _, _ in scan_backlog_iter(repo_path, profile)
        if item is not None
    ]
    backlog.sort(key=lambda x: x["risk_score"], reverse=True)
    return backlog


# ---------------------------------------------------------------------------
# AI-generated explanations via IBM watsonx.ai
# Credentials are injected by app.py via set_watsonx_credentials().
# Falls back to the rule-based summary when credentials aren't provided.
# ---------------------------------------------------------------------------
_watsonx_credentials: dict | None = None


def set_watsonx_credentials(api_key: str, project_id: str, url: str) -> None:
    """Called once by app.py after the user enters their watsonx credentials."""
    global _watsonx_credentials
    _watsonx_credentials = {"api_key": api_key, "project_id": project_id, "url": url}


def call_ai_for_explanation(file_snippet: str, metrics: dict) -> str:
    """
    Returns a one-sentence plain-English explanation of why this file is risky.

    When watsonx credentials are available (set via set_watsonx_credentials)
    the explanation is generated by ibm/granite-3-3-8b-instruct on watsonx.ai.
    Otherwise falls back to a concise rule-based summary.
    """
    if not _watsonx_credentials:
        # Graceful fallback — works with no credentials at all
        reasons = metrics.get("risky_findings") or ["general complexity/staleness risk"]
        return " | ".join(reasons)

    try:
        from ibm_watsonx_ai import Credentials
        from ibm_watsonx_ai.foundation_models import ModelInference

        creds = _watsonx_credentials
        findings_text = (
            ", ".join(metrics["risky_findings"])
            if metrics.get("risky_findings")
            else "general complexity and staleness"
        )
        prompt = (
            f"You are a senior software engineer reviewing a code audit report.\n"
            f"File: {metrics['file']}\n"
            f"Risk score: {metrics.get('risk_score', 'N/A')} / 100\n"
            f"Lines of code: {metrics.get('line_count', 'N/A')}\n"
            f"Days since last change: {metrics.get('staleness_days', 'N/A')}\n"
            f"Has test file: {'Yes' if metrics.get('has_test') else 'No'}\n"
            f"Flagged issues: {findings_text}\n\n"
            f"In exactly one concise sentence, explain to a developer why this file "
            f"is a priority to fix and what the main risk is."
        )

        model = ModelInference(
            model_id="ibm/granite-3-3-8b-instruct",
            credentials=Credentials(api_key=creds["api_key"], url=creds["url"]),
            project_id=creds["project_id"],
            params={"max_new_tokens": 80, "temperature": 0.2},
        )
        return model.generate_text(prompt).strip()

    except Exception as exc:  # never crash the whole app for a missing explanation
        reasons = metrics.get("risky_findings") or ["general complexity/staleness risk"]
        return " | ".join(reasons) + f"  _(AI unavailable: {exc})_"


def call_ai_for_repo_summary(backlog: list, profile_label: str = "Default") -> str:
    """
    Returns a one-paragraph plain-English health summary of the whole repo.

    Uses the top-5 highest-risk files plus aggregate stats to give engineers
    an executive-level view of what's most broken and why.

    Falls back to a rule-based paragraph when watsonx credentials are absent.
    """
    if not backlog:
        return ""

    total       = len(backlog)
    high        = sum(1 for b in backlog if b["risk_score"] >= 70)
    medium      = sum(1 for b in backlog if 40 <= b["risk_score"] < 70)
    low         = total - high - medium
    avg_score   = round(sum(b["risk_score"] for b in backlog) / total, 1)
    untested    = sum(1 for b in backlog if not b.get("has_test"))
    top5        = backlog[:5]
    top5_lines  = "\n".join(
        f"  • {b['file']} (score {b['risk_score']}, "
        f"{len(b.get('risky_findings') or []) + len(b.get('compliance_findings') or [])} finding(s))"
        for b in top5
    )

    if not _watsonx_credentials:
        # ── Rule-based fallback ────────────────────────────────────────────────
        urgency = "critical" if high > total * 0.3 else "moderate" if high > 0 else "low"
        return (
            f"This codebase contains **{total} scanned files** with an average risk score of "
            f"**{avg_score} / 100** under the **{profile_label}** scoring profile. "
            f"**{high} files are high-risk**, {medium} medium-risk, and {low} low-risk. "
            f"**{untested} files lack a matching test**, increasing the overall exposure. "
            f"Overall health urgency is assessed as **{urgency}**. "
            f"The highest-priority files to address are: "
            + ", ".join(f"`{b['file']}`" for b in top5) + "."
        )

    try:
        from ibm_watsonx_ai import Credentials
        from ibm_watsonx_ai.foundation_models import ModelInference

        creds = _watsonx_credentials
        prompt = (
            f"You are a principal software engineer delivering an executive code-health report.\n"
            f"Scoring profile: {profile_label}\n"
            f"Repository stats:\n"
            f"  Total files scanned: {total}\n"
            f"  Average risk score:  {avg_score} / 100\n"
            f"  High-risk files (≥70):   {high}\n"
            f"  Medium-risk files (40–69): {medium}\n"
            f"  Low-risk files (<40):    {low}\n"
            f"  Files with no test:      {untested}\n"
            f"Top 5 highest-risk files:\n{top5_lines}\n\n"
            f"Write exactly one paragraph (3–5 sentences) for a technical audience summarising "
            f"the overall health of this repository, the biggest risk areas, and the most "
            f"important remediation priorities. Be direct and specific. Do not use bullet points."
        )

        model = ModelInference(
            model_id="ibm/granite-3-3-8b-instruct",
            credentials=Credentials(api_key=creds["api_key"], url=creds["url"]),
            project_id=creds["project_id"],
            params={"max_new_tokens": 220, "temperature": 0.3},
        )
        return model.generate_text(prompt).strip()

    except Exception as exc:
        # Fallback to rule-based on any API failure
        return (
            f"This codebase contains **{total} scanned files** (avg score {avg_score} / 100, "
            f"profile: {profile_label}). {high} high-risk, {medium} medium-risk, {low} low-risk. "
            f"{untested} files lack tests. _(AI summary unavailable: {exc})_"
        )


if __name__ == "__main__":
    # Quick manual test: run `python3 analyzer.py` to see it work on itself.
    import json

    this_repo = os.path.dirname(os.path.abspath(__file__))
    results = build_backlog(this_repo)
    print(json.dumps(results[:5], indent=2))
