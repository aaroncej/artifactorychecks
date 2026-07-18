#!/usr/bin/env python3
"""
Compares two JFrog Artifactory clusters (users, groups, permissions, repos,
storage size, and per-repo details) via the Artifactory REST API and emails
an HTML tabular report of the results.

Configuration is read from a JSON file (see config.example.json) and/or
environment variables, which always take precedence over the file:

  ARTIFACTORY_A_NAME, ARTIFACTORY_A_URL, ARTIFACTORY_A_TOKEN
  ARTIFACTORY_B_NAME, ARTIFACTORY_B_URL, ARTIFACTORY_B_TOKEN
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_USE_TLS
  EMAIL_FROM, EMAIL_TO (comma-separated), EMAIL_SUBJECT

Auth uses a bearer access token (JFrog's recommended method). For instances
still relying on API keys, swap the Authorization header in ArtifactoryClient
for "X-JFrog-Art-Api".

Usage:
  python artifactory_sync_check.py --config config.json
  python artifactory_sync_check.py --config config.json --dry-run report.html
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import smtplib
import sys
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

DEFAULT_TIMEOUT = 30
DEFAULT_SIZE_DIFF_THRESHOLD_PCT = 1.0  # tolerate small drift from in-flight replication


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

@dataclass
class ClusterConfig:
    name: str
    url: str
    token: str
    verify_ssl: bool = True
    timeout: int = DEFAULT_TIMEOUT


@dataclass
class EmailConfig:
    smtp_host: str
    smtp_port: int = 587
    use_tls: bool = True
    username: Optional[str] = None
    password: Optional[str] = None
    from_addr: str = ""
    to_addrs: List[str] = field(default_factory=list)
    subject: str = "Artifactory Cluster Sync Report"


def _env_override(value: Optional[str], env_var: str) -> Optional[str]:
    return os.environ.get(env_var, value)


def load_config(path: Optional[str]) -> Dict[str, Any]:
    raw: Dict[str, Any] = {}
    if path and os.path.exists(path):
        with open(path, "r") as f:
            raw = json.load(f)

    clusters_raw = raw.get("clusters", {})
    a_raw = clusters_raw.get("cluster_a", {})
    b_raw = clusters_raw.get("cluster_b", {})

    cluster_a = ClusterConfig(
        name=_env_override(a_raw.get("name", "Cluster A"), "ARTIFACTORY_A_NAME"),
        url=_env_override(a_raw.get("url"), "ARTIFACTORY_A_URL").rstrip("/"),
        token=_env_override(a_raw.get("token"), "ARTIFACTORY_A_TOKEN"),
        verify_ssl=raw.get("verify_ssl", True),
        timeout=raw.get("timeout", DEFAULT_TIMEOUT),
    )
    cluster_b = ClusterConfig(
        name=_env_override(b_raw.get("name", "Cluster B"), "ARTIFACTORY_B_NAME"),
        url=_env_override(b_raw.get("url"), "ARTIFACTORY_B_URL").rstrip("/"),
        token=_env_override(b_raw.get("token"), "ARTIFACTORY_B_TOKEN"),
        verify_ssl=raw.get("verify_ssl", True),
        timeout=raw.get("timeout", DEFAULT_TIMEOUT),
    )

    email_raw = raw.get("email", {})
    to_addrs_raw = _env_override(
        ",".join(email_raw.get("to_addrs", [])) if email_raw.get("to_addrs") else None,
        "EMAIL_TO",
    )
    email_cfg = EmailConfig(
        smtp_host=_env_override(email_raw.get("smtp_host"), "SMTP_HOST"),
        smtp_port=int(_env_override(str(email_raw.get("smtp_port", 587)), "SMTP_PORT")),
        use_tls=str(_env_override(str(email_raw.get("use_tls", True)), "SMTP_USE_TLS")).lower() == "true",
        username=_env_override(email_raw.get("username"), "SMTP_USER"),
        password=_env_override(email_raw.get("password"), "SMTP_PASS"),
        from_addr=_env_override(email_raw.get("from_addr"), "EMAIL_FROM"),
        to_addrs=[a.strip() for a in (to_addrs_raw or "").split(",") if a.strip()],
        subject=_env_override(email_raw.get("subject", EmailConfig.subject), "EMAIL_SUBJECT"),
    )

    if not cluster_a.url or not cluster_b.url:
        raise SystemExit("Both cluster URLs must be set (config file or ARTIFACTORY_A_URL/ARTIFACTORY_B_URL).")

    return {"cluster_a": cluster_a, "cluster_b": cluster_b, "email": email_cfg}


# --------------------------------------------------------------------------
# Artifactory REST client
# --------------------------------------------------------------------------

class ArtifactoryClient:
    def __init__(self, cfg: ClusterConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {cfg.token}",
            "Accept": "application/json",
        })

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        url = f"{self.cfg.url}{path}"
        resp = self.session.get(
            url, params=params, timeout=self.cfg.timeout, verify=self.cfg.verify_ssl
        )
        resp.raise_for_status()
        return resp.json()

    def get_version(self) -> Dict[str, Any]:
        return self._get("/api/system/version")

    def get_users(self) -> List[dict]:
        return self._get("/api/security/users")

    def get_groups(self) -> List[dict]:
        return self._get("/api/security/groups")

    def get_permission_targets(self) -> List[dict]:
        return self._get("/api/security/permissions")

    def get_repositories(self) -> List[dict]:
        return self._get("/api/repositories")

    def get_storage_info(self) -> Dict[str, Any]:
        return self._get("/api/storageinfo")


# --------------------------------------------------------------------------
# Metric collection
# --------------------------------------------------------------------------

def human_size(num_bytes: Any) -> str:
    try:
        n = float(num_bytes)
    except (TypeError, ValueError):
        return "N/A"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} EB"


def collect_metrics(client: ArtifactoryClient) -> Dict[str, Any]:
    """Fetch all metrics for one cluster. Raises on hard failure (e.g. auth/network)."""
    version = client.get_version()
    users = client.get_users()
    groups = client.get_groups()
    perms = client.get_permission_targets()
    repos = client.get_repositories()
    storage = client.get_storage_info()

    repos_by_type: Dict[str, int] = {}
    for r in repos:
        rtype = r.get("type", "unknown")
        repos_by_type[rtype] = repos_by_type.get(rtype, 0) + 1

    binaries_summary = storage.get("binariesSummary", {})
    per_repo: Dict[str, Dict[str, Any]] = {}
    for entry in storage.get("repositoriesSummaryList", []):
        key = entry.get("repoKey")
        if not key or key.upper() == "TOTAL":
            continue
        used_space = entry.get("usedSpace", "0")
        # usedSpace from this endpoint is a human string in older versions; try both.
        per_repo[key] = {
            "type": entry.get("repoType"),
            "package_type": entry.get("packageType"),
            "items_count": entry.get("itemsCount", 0),
            "files_count": entry.get("filesCount", 0),
            "used_space_raw": used_space,
        }

    return {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "version": version.get("version", "unknown"),
        "users_count": len(users),
        "groups_count": len(groups),
        "permission_targets_count": len(perms),
        "repos_total": len(repos),
        "repos_by_type": repos_by_type,
        "artifacts_count": binaries_summary.get("artifactsCount", "N/A"),
        "artifacts_size_bytes": binaries_summary.get("artifactsSize"),
        "binaries_count": binaries_summary.get("binariesCount", "N/A"),
        "binaries_size_bytes": binaries_summary.get("binariesSize"),
        "per_repo": per_repo,
    }


def collect_metrics_safe(name: str, client: ArtifactoryClient) -> Dict[str, Any]:
    try:
        return collect_metrics(client)
    except Exception as exc:  # noqa: BLE001 - surfaced in the report, not swallowed
        return {"error": f"Failed to query {name}: {exc}"}


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def compare_summary(m_a: dict, m_b: dict) -> List[Dict[str, Any]]:
    rows = [
        ("Artifactory Version", "version", "version"),
        ("Users", "users_count", "users_count"),
        ("Groups", "groups_count", "groups_count"),
        ("Permission Targets", "permission_targets_count", "permission_targets_count"),
        ("Total Repositories", "repos_total", "repos_total"),
        ("Artifacts Count", "artifacts_count", "artifacts_count"),
        ("Binaries Count", "binaries_count", "binaries_count"),
    ]
    out = []
    for label, key_a, key_b in rows:
        val_a = m_a.get(key_a, "N/A")
        val_b = m_b.get(key_b, "N/A")
        out.append({"metric": label, "a": val_a, "b": val_b, "match": val_a == val_b})

    # Sizes compared separately with human-readable formatting
    for label, key in (("Artifacts Size", "artifacts_size_bytes"), ("Binaries Size", "binaries_size_bytes")):
        val_a = m_a.get(key)
        val_b = m_b.get(key)
        out.append({
            "metric": label,
            "a": human_size(val_a),
            "b": human_size(val_b),
            "match": val_a == val_b,
        })

    # Repo type breakdown (local/remote/virtual/federated)
    types = sorted(set(m_a.get("repos_by_type", {})) | set(m_b.get("repos_by_type", {})))
    for t in types:
        val_a = m_a.get("repos_by_type", {}).get(t, 0)
        val_b = m_b.get("repos_by_type", {}).get(t, 0)
        out.append({
            "metric": f"Repos ({t})",
            "a": val_a,
            "b": val_b,
            "match": val_a == val_b,
        })

    return out


def compare_repos(m_a: dict, m_b: dict, threshold_pct: float) -> List[Dict[str, Any]]:
    repos_a = m_a.get("per_repo", {})
    repos_b = m_b.get("per_repo", {})
    all_keys = sorted(set(repos_a) | set(repos_b))

    rows = []
    for key in all_keys:
        ra = repos_a.get(key)
        rb = repos_b.get(key)
        status = "OK"
        if ra is None:
            status = "MISSING in A"
        elif rb is None:
            status = "MISSING in B"
        else:
            items_a, items_b = ra.get("items_count", 0), rb.get("items_count", 0)
            if items_a != items_b:
                denom = max(items_a, items_b, 1)
                pct_diff = abs(items_a - items_b) / denom * 100
                status = "OK" if pct_diff <= threshold_pct else "MISMATCH"

        rows.append({
            "repo": key,
            "type_a": (ra or {}).get("type", "-"),
            "type_b": (rb or {}).get("type", "-"),
            "items_a": (ra or {}).get("items_count", "-"),
            "items_b": (rb or {}).get("items_count", "-"),
            "space_a": (ra or {}).get("used_space_raw", "-"),
            "space_b": (rb or {}).get("used_space_raw", "-"),
            "status": status,
        })
    return rows


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

STYLE = """
<style>
  body { font-family: Arial, Helvetica, sans-serif; color: #222; }
  h2 { margin-bottom: 4px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 24px; font-size: 13px; }
  th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
  th { background-color: #2d3e50; color: #fff; }
  tr:nth-child(even) { background-color: #f6f8fa; }
  .match { color: #1a7f37; font-weight: bold; }
  .mismatch { background-color: #ffe0e0; color: #a40000; font-weight: bold; }
  .caption { color: #555; font-size: 12px; margin-bottom: 12px; }
</style>
"""


def render_summary_table(rows: List[Dict[str, Any]], name_a: str, name_b: str) -> str:
    body = ""
    for r in rows:
        cls = "match" if r["match"] else "mismatch"
        status = "MATCH" if r["match"] else "MISMATCH"
        body += (
            f"<tr><td>{r['metric']}</td><td>{r['a']}</td><td>{r['b']}</td>"
            f"<td class='{cls}'>{status}</td></tr>\n"
        )
    return (
        "<h2>Summary Metrics</h2>"
        f"<table><tr><th>Metric</th><th>{name_a}</th><th>{name_b}</th><th>Status</th></tr>\n"
        f"{body}</table>"
    )


def render_repo_table(rows: List[Dict[str, Any]], name_a: str, name_b: str) -> str:
    mismatches = [r for r in rows if r["status"] != "OK"]
    display_rows = mismatches if mismatches else rows
    caption = (
        f"Showing {len(mismatches)} repo(s) with discrepancies out of {len(rows)} total."
        if mismatches else f"All {len(rows)} repositories are in sync."
    )
    body = ""
    for r in display_rows:
        cls = "match" if r["status"] == "OK" else "mismatch"
        body += (
            f"<tr><td>{r['repo']}</td><td>{r['type_a']}</td><td>{r['type_b']}</td>"
            f"<td>{r['items_a']}</td><td>{r['items_b']}</td>"
            f"<td>{r['space_a']}</td><td>{r['space_b']}</td>"
            f"<td class='{cls}'>{r['status']}</td></tr>\n"
        )
    return (
        "<h2>Repository-Level Comparison</h2>"
        f"<div class='caption'>{caption}</div>"
        "<table><tr><th>Repo</th>"
        f"<th>Type ({name_a})</th><th>Type ({name_b})</th>"
        f"<th>Items ({name_a})</th><th>Items ({name_b})</th>"
        f"<th>Used Space ({name_a})</th><th>Used Space ({name_b})</th>"
        "<th>Status</th></tr>\n"
        f"{body}</table>"
    )


def render_report(
    name_a: str, name_b: str, m_a: dict, m_b: dict, threshold_pct: float
) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if "error" in m_a or "error" in m_b:
        errors = "<br>".join(m.get("error", "") for m in (m_a, m_b) if "error" in m)
        return (
            f"<html><head>{STYLE}</head><body>"
            f"<h2>Artifactory Sync Report - ERROR</h2>"
            f"<p class='mismatch'>{errors}</p>"
            f"<div class='caption'>Generated {generated_at}</div>"
            "</body></html>"
        )

    summary_rows = compare_summary(m_a, m_b)
    repo_rows = compare_repos(m_a, m_b, threshold_pct)
    overall_ok = all(r["match"] for r in summary_rows) and all(r["status"] == "OK" for r in repo_rows)
    overall_label = (
        "<span class='match'>IN SYNC</span>" if overall_ok else "<span class='mismatch'>OUT OF SYNC</span>"
    )

    return (
        f"<html><head>{STYLE}</head><body>"
        f"<h2>Artifactory Cluster Sync Report: {overall_label}</h2>"
        f"<div class='caption'>Comparing <b>{name_a}</b> vs <b>{name_b}</b> &mdash; generated {generated_at} "
        f"(repo item-count mismatch threshold: {threshold_pct}%)</div>"
        f"{render_summary_table(summary_rows, name_a, name_b)}"
        f"{render_repo_table(repo_rows, name_a, name_b)}"
        "</body></html>"
    )


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------

def send_email(email_cfg: EmailConfig, html_body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = email_cfg.subject
    msg["From"] = email_cfg.from_addr
    msg["To"] = ", ".join(email_cfg.to_addrs)
    msg.attach(MIMEText("This report requires an HTML-capable email client.", "plain"))
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(email_cfg.smtp_host, email_cfg.smtp_port, timeout=30) as server:
        if email_cfg.use_tls:
            server.starttls()
        if email_cfg.username and email_cfg.password:
            server.login(email_cfg.username, email_cfg.password)
        server.sendmail(email_cfg.from_addr, email_cfg.to_addrs, msg.as_string())


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="config.json", help="Path to JSON config file")
    parser.add_argument(
        "--dry-run", metavar="OUTPUT_HTML", default=None,
        help="Write the report to a local HTML file instead of emailing it",
    )
    parser.add_argument(
        "--size-diff-threshold-pct", type=float, default=DEFAULT_SIZE_DIFF_THRESHOLD_PCT,
        help="Allowed %% difference in per-repo item counts before flagging a mismatch",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    cluster_a_cfg: ClusterConfig = cfg["cluster_a"]
    cluster_b_cfg: ClusterConfig = cfg["cluster_b"]
    email_cfg: EmailConfig = cfg["email"]

    client_a = ArtifactoryClient(cluster_a_cfg)
    client_b = ArtifactoryClient(cluster_b_cfg)

    print(f"Querying {cluster_a_cfg.name} ({cluster_a_cfg.url}) ...", file=sys.stderr)
    metrics_a = collect_metrics_safe(cluster_a_cfg.name, client_a)
    print(f"Querying {cluster_b_cfg.name} ({cluster_b_cfg.url}) ...", file=sys.stderr)
    metrics_b = collect_metrics_safe(cluster_b_cfg.name, client_b)

    html = render_report(
        cluster_a_cfg.name, cluster_b_cfg.name, metrics_a, metrics_b, args.size_diff_threshold_pct
    )

    if args.dry_run:
        with open(args.dry_run, "w") as f:
            f.write(html)
        print(f"Report written to {args.dry_run}", file=sys.stderr)
    else:
        send_email(email_cfg, html)
        print(f"Report emailed to {', '.join(email_cfg.to_addrs)}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
