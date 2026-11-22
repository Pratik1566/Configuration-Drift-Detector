"""Core logic (no UI): file parsing, drift detection, risk rules, scoring, reports.

The rule-based engine is authoritative. AI explanations, if enabled by the UI,
must never change findings, severities, or posture scores.
"""

import csv
import hashlib
import io
import json
import re
from datetime import datetime

from security_baseline import STANDARD_SECURITY_BASELINE


# ---------------------------------------------------------------------------
# Labels and deterministic risk scoring

SETTING_LABELS = {
    "firewall_enabled": "Firewall",
    "ssh_password_login": "SSH password login",
    "ssh_root_login": "SSH root login",
    "open_ports": "Open ports",
    "password_min_length": "Minimum password length",
    "auto_updates": "Automatic updates",
    "log_level": "Log level",
    "telnet_enabled": "Telnet service",
    "permit_empty_passwords": "Empty passwords allowed",
    "x11_forwarding": "X11 forwarding",
    "max_auth_tries": "Max authentication attempts",
    "ssh_port": "SSH port",
}

# Risk is decided by rules, never by AI. Unknown custom settings default to Medium.
LEGACY_SCORE_RULES = {
    # severity, impact, exposure, compliance
    "firewall_enabled": (100, 90, 80, 90),
    "ssh_password_login": (85, 80, 85, 75),
    "logging_enabled": (75, 65, 40, 80),
    "security_updates": (90, 85, 70, 85),
}


def legacy_finding_score(setting: str, actual):
    """Return the legacy weighted score for an existing data.py record."""
    weights = LEGACY_SCORE_RULES.get(setting)
    if weights is None:
        return 0

    # These legacy rules describe the unsafe state as False for all four
    # settings except ssh_password_login, where True is unsafe.
    unsafe = actual is True if setting == "ssh_password_login" else actual is False
    if not unsafe:
        return 0

    severity, impact, exposure, compliance = weights
    return round(
        0.4 * severity
        + 0.3 * impact
        + 0.2 * exposure
        + 0.1 * compliance
    )


RISK_RULES = {
    "firewall_enabled": "High",
    "ssh_password_login": "High",
    "ssh_root_login": "High",
    "open_ports": "High",
    "telnet_enabled": "High",
    "permit_empty_passwords": "High",
    "password_min_length": "Medium",
    "auto_updates": "Medium",
    "max_auth_tries": "Medium",
    "log_level": "Low",
    "x11_forwarding": "Low",
    "ssh_port": "Low",
}

# Critical findings are displayed as Critical, but use the existing High
# penalty so that the score scale remains compatible with the dashboard.
RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
PENALTY = {"Critical": 15, "High": 15, "Medium": 7, "Low": 2}
DOT = {
    "Critical": "#FF3B30",
    "High": "#FF3B30",
    "Medium": "#FF9F0A",
    "Low": "#34C759",
    "None": "#34C759",
}
TYPE_LABEL = {
    "modified": "Modified",
    "added": "Added",
    "removed": "Removed",
    "same": "Unchanged",
}

# Kept for compatibility with UI code that may still import this constant.
# Standard-mode comparisons use STANDARD_SECURITY_BASELINE below.
STANDARD_BASELINE = {
    "firewall_enabled": True,
    "open_ports": [22, 443],
    "telnet_enabled": False,
    "ssh_password_login": False,
    "ssh_root_login": False,
    "permit_empty_passwords": False,
    "max_auth_tries": 4,
    "password_min_length": 12,
    "pubkey_authentication": True,
    "strict_modes": True,
    "ignore_rhosts": True,
    "x11_forwarding": False,
    "allow_tcp_forwarding": False,
    "client_alive_interval": 300,
    "client_alive_count_max": 3,
    "compression": False,
    "auto_updates": True,
    "log_level": "info",
    "port": 22,
    "protocol": 2,
}


def label(key: str) -> str:
    return SETTING_LABELS.get(key) or key.replace("_", " ").capitalize()


# ---------------------------------------------------------------------------
# File parsing

class ConfigError(ValueError):
    """A problem with an uploaded file, worded for the end user."""


MAX_BYTES = 2_000_000
BOOL = {
    "yes": True,
    "no": False,
    "true": True,
    "false": False,
    "on": True,
    "off": False,
}

# sshd keyword (lower-case) -> normalised setting name.
SSH_ALIASES = {
    "passwordauthentication": "ssh_password_login",
    "permitrootlogin": "ssh_root_login",
    "permitemptypasswords": "permit_empty_passwords",
    "x11forwarding": "x11_forwarding",
    "maxauthtries": "max_auth_tries",
    "loglevel": "log_level",
    "port": "ssh_port",
}

SSH_MULTI = {
    "hostkey",
    "listenaddress",
    "acceptenv",
    "subsystem",
    "allowusers",
    "allowgroups",
    "denyusers",
    "denygroups",
    "include",
}

SSH_KNOWN = set(SSH_ALIASES) | SSH_MULTI | {
    "protocol", "syslogfacility", "logingracetime", "strictmodes",
    "pubkeyauthentication", "authorizedkeysfile", "usepam",
    "challengeresponseauthentication", "kbdinteractiveauthentication",
    "printmotd", "printlastlog", "clientaliveinterval",
    "clientalivecountmax", "usedns", "allowtcpforwarding",
    "gatewayports", "permittunnel", "maxsessions", "maxstartups",
    "banner", "ciphers", "macs", "kexalgorithms", "ignorerhosts",
    "hostbasedauthentication", "permituserenvironment", "compression",
    "tcpkeepalive", "authenticationmethods", "permittty",
    "chrootdirectory", "forcecommand", "allowagentforwarding",
    "addressfamily", "uselogin", "useprivilegeseparation",
    "ignoreuserknownhosts", "kerberosauthentication",
    "kerberosorlocalpasswd", "kerberosticketcleanup",
    "gssapiauthentication", "gssapicleanupcredentials",
    "x11uselocalhost", "debianbanner",
}

# Built-in SSH baseline setting -> parsed SSH setting.
SSH_BASELINE_ALIASES = {
    "Ciphers": "ciphers",
    "KexAlgorithms": "kex_algorithms",
    "MACs": "macs",
    "PermitRootLogin": "ssh_root_login",
    "Port": "ssh_port",
    "AddressFamily": "address_family",
    "ListenAddress": "listen_address",
    "StrictModes": "strict_modes",
    "SyslogFacility": "syslog_facility",
    "LogLevel": "log_level",
    "HostKey": "host_key",
    "UseLogin": "use_login",
    "UsePrivilegeSeparation": "use_privilege_separation",
    "PermitUserEnvironment": "permit_user_environment",
    "LoginGraceTime": "login_grace_time",
    "MaxAuthTries": "max_auth_tries",
    "MaxSessions": "max_sessions",
    "MaxStartups": "max_startups",
    "PubkeyAuthentication": "pubkey_authentication",
    "IgnoreRhosts": "ignore_rhosts",
    "IgnoreUserKnownHosts": "ignore_user_known_hosts",
    "HostbasedAuthentication": "hostbased_authentication",
    "PasswordAuthentication": "ssh_password_login",
    "PermitEmptyPasswords": "permit_empty_passwords",
    "ChallengeResponseAuthentication": "challenge_response_authentication",
    "KerberosAuthentication": "kerberos_authentication",
    "KerberosOrLocalPasswd": "kerberos_or_local_passwd",
    "KerberosTicketCleanup": "kerberos_ticket_cleanup",
    "GSSAPIAuthentication": "gssapi_authentication",
    "GSSAPICleanupCredentials": "gssapi_cleanup_credentials",
    "TCPKeepAlive": "tcp_keep_alive",
    "ClientAliveInterval": "client_alive_interval",
    "ClientAliveCountMax": "client_alive_count_max",
    "PermitTunnel": "permit_tunnel",
    "AllowTcpForwarding": "allow_tcp_forwarding",
    "AllowAgentForwarding": "allow_agent_forwarding",
    "GatewayPorts": "gateway_ports",
    "X11Forwarding": "x11_forwarding",
    "X11UseLocalhost": "x11_use_localhost",
    "PrintMotd": "print_motd",
    "PrintLastLog": "print_last_log",
    "Banner": "banner",
    "DebianBanner": "debian_banner",
}

# Allow JSON uploads to use either OpenSSH keyword names or normalised names.
_SSH_JSON_ALIASES = {
    **{key.lower(): value for key, value in SSH_BASELINE_ALIASES.items()},
    **SSH_ALIASES,
}


def _snake(name: str) -> str:
    """Convert CamelCase SSH keywords to snake_case."""
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()


def _coerce(value: str):
    """Convert simple textual booleans and integers to native values."""
    value = value.strip()
    low = value.lower()
    if low in BOOL:
        return BOOL[low]
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def parse_ssh(text: str) -> dict:
    """Parse the supported portion of an sshd_config file.

    This is a file-level parser, not an OpenSSH effective-configuration
    evaluator. Include files and Match-specific blocks are not expanded.
    """
    out = {}
    ports = []
    known_seen = 0

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(
            r"^([A-Za-z][A-Za-z0-9]*)(?:\s*=\s*|\s+)(.+)$",
            line,
        )
        if not match:
            continue

        key = match.group(1)
        value = re.sub(r"\s+#.*$", "", match.group(2)).strip().strip('"')
        low = key.lower()

        # Match blocks have conditional semantics; do not pretend to parse
        # them as global settings.
        if low == "match":
            break

        if low in SSH_KNOWN:
            known_seen += 1

        if low == "port":
            if value.isdigit():
                ports.append(int(value))
            continue

        # Include paths are not expanded by this upload-only parser.
        if low == "include":
            continue

        name = SSH_ALIASES.get(low) or _snake(key)

        if low in SSH_MULTI:
            out.setdefault(name, []).append(value)
        elif name not in out:
            # OpenSSH generally uses the first obtained value for most
            # keywords; this parser follows that simplified file-level rule.
            out[name] = value.lower() if low == "loglevel" else _coerce(value)

    if not known_seen:
        raise ConfigError(
            "This doesn't look like an SSH config (sshd_config). "
            "Upload a JSON object of settings or an sshd_config file."
        )

    if ports:
        out["ssh_port"] = sorted(set(ports))

    return out


def parse_json(text: str, filename: str) -> dict:
    """Parse a non-empty JSON object and normalise known SSH keyword names."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"{filename} is not valid JSON "
            f"(line {exc.lineno}, column {exc.colno}: {exc.msg})."
        ) from exc

    if not isinstance(data, dict) or not data:
        raise ConfigError(
            f"{filename} must contain a JSON object of settings, "
            'for example {"firewall_enabled": true}.'
        )

    out = {}
    for key, value in data.items():
        original_key = str(key)
        normalised = _SSH_JSON_ALIASES.get(original_key.lower())

        if normalised:
            key = normalised
            if isinstance(value, str):
                value = _coerce(value)
        else:
            key = original_key

        out[str(key)] = value

    return out


def parse_sysctl(text: str) -> dict:
    """Parse Linux sysctl configuration settings."""
    settings = {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(
            r"^([A-Za-z0-9_.-]+)\s*(?:=|\s)\s*(.*?)\s*$",
            line,
        )
        if not match:
            continue

        key, value = match.groups()
        value = value.split("#", 1)[0].strip()
        if value:
            settings[key] = _coerce(value)

    return settings


def parse_nginx(text: str) -> dict:
    """Parse the NGINX directive currently supported automatically."""
    settings = {}
    matches = re.findall(r"(?mi)^\s*server_tokens\s+([^;]+)\s*;", text)
    if matches:
        settings["server_tokens"] = matches[-1].strip().lower()
    return settings


def parse_config(filename: str, data: bytes) -> tuple[dict, str]:
    """Detect and parse JSON, Ubuntu sysctl, SSH, or supported NGINX config."""
    if not isinstance(data, bytes):
        raise ConfigError("The uploaded configuration could not be read as bytes.")

    if len(data) > MAX_BYTES:
        raise ConfigError(
            f"{filename} is larger than 2 MB. Upload just the configuration file."
        )

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(
            f"{filename} is not a UTF-8 text file. "
            "Upload a JSON or text configuration file."
        ) from exc

    if "\x00" in text:
        raise ConfigError(
            f"{filename} is not a text file. Upload a JSON or text config file."
        )

    stripped = text.lstrip()
    if not stripped:
        raise ConfigError(f"{filename} is empty.")

    lower_name = filename.lower()

    if lower_name.endswith(".json") or stripped[0] in "{[":
        return parse_json(text, filename), "json"

    # Detect Ubuntu sysctl configuration.
    if re.search(
        r"(?m)^\s*(?:net|kernel|fs)\.[A-Za-z0-9_.-]+\s*(?:=|\s)",
        text,
    ):
        settings = parse_sysctl(text)
        if settings:
            return settings, "ubuntu_22_04"

    # NGINX parsing is intentionally limited to supported directives.
    if lower_name.endswith((".conf", ".nginx")) and (
        "server_tokens" in text
        or re.search(r"(?m)^\s*(?:events|http|server|upstream)\s*\{", text)
    ):
        return parse_nginx(text), "nginx"

    return parse_ssh(text), "ssh"


# ---------------------------------------------------------------------------
# Standard baseline selection and evaluation

def select_standard_group(current: dict, current_kind: str, filename: str) -> str:
    """Select the built-in baseline group matching the uploaded configuration."""
    if current_kind in STANDARD_SECURITY_BASELINE:
        return current_kind

    keys = set(current)

    if any(key.startswith(("net.", "kernel.", "fs.")) for key in keys):
        return "ubuntu_22_04"

    if "server_tokens" in keys or filename.lower().endswith((".nginx",)):
        return "nginx"

    ssh_keys = (
        set(SSH_BASELINE_ALIASES.values())
        | set(SSH_ALIASES.values())
        | {
            "ssh_password_login",
            "ssh_root_login",
            "ssh_port",
            "max_auth_tries",
            "permit_empty_passwords",
            "ciphers",
            "kex_algorithms",
            "macs",
        }
    )
    if keys.intersection(ssh_keys):
        return "ssh"

    raise ConfigError(
        f"Could not identify the standard baseline platform for {filename}. "
        "Use an SSH config, Ubuntu sysctl config, NGINX config, or a JSON file "
        "containing recognisable settings for one of those platforms."
    )


def get_rule_setting(rule: dict, group: str) -> str:
    """Map a rule setting name to the parser's normalised setting name."""
    setting = rule["setting"]
    if group == "ssh":
        return SSH_BASELINE_ALIASES.get(setting, _snake(setting))
    return setting


def comparable_value(value):
    """Normalise simple values for comparison without changing their meaning."""
    if isinstance(value, str):
        value = value.strip()
        low = value.lower()
        if low in BOOL:
            return BOOL[low]
        if re.fullmatch(r"-?\d+", value):
            return int(value)
        return low

    if isinstance(value, list):
        return sorted(
            (comparable_value(item) for item in value),
            key=lambda item: str(item),
        )

    return value


def evaluate_rule(rule: dict, actual):
    """Return True (pass), False (drift), or None (not automatable here)."""
    check_type = rule["check_type"]
    expected = rule["expected"]

    if check_type in {"custom", "file_permission", "manual"}:
        return None

    if check_type == "equals":
        return comparable_value(actual) == comparable_value(expected)

    if check_type in {"value", "one_of"}:
        if isinstance(expected, list):
            accepted = [comparable_value(value) for value in expected]
            if isinstance(actual, list):
                return all(
                    comparable_value(value) in accepted for value in actual
                )
            return comparable_value(actual) in accepted
        return comparable_value(actual) == comparable_value(expected)

    if check_type == "contains":
        if isinstance(actual, (list, tuple, set)):
            return comparable_value(expected) in [
                comparable_value(value) for value in actual
            ]
        return str(expected).lower() in str(actual).lower()

    if check_type == "not_empty":
        return actual is not None and str(actual).strip() != ""

    if check_type == "regex":
        try:
            return re.search(str(expected), str(actual)) is not None
        except re.error:
            # An invalid baseline expression is not a pass or a drift finding.
            return None

    return None


def evaluate_standard_rules(run: dict) -> tuple[list, list]:
    """Evaluate automatic rules and collect checks needing manual review."""
    findings = []
    manual_checks = []

    for rule in run["rules"]:
        setting = get_rule_setting(rule, run["rule_group"])
        check_type = rule["check_type"]

        if not rule["automatic"] or check_type == "manual":
            manual_checks.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "setting": setting,
                "reason": "Requires manual verification",
            })
            continue

        if check_type in {"custom", "file_permission"}:
            manual_checks.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "setting": setting,
                "reason": (
                    f"{check_type} check is not implemented for uploaded files yet"
                ),
            })
            continue

        # Runtime/host checks cannot be verified from an uploaded config file.
        if setting.startswith("/"):
            manual_checks.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "setting": setting,
                "reason": (
                    "Requires host information outside the uploaded configuration"
                ),
            })
            continue

        # Product policy: missing automatic settings are potential drift.
        # This does not evaluate OpenSSH/Linux runtime defaults.
        if setting not in run["current"]:
            findings.append({
                "rule_id": rule["id"],
                "setting": setting,
                "title": rule["title"],
                "type": "removed",
                "expected": rule["expected"],
                "actual": None,
                "severity": rule["severity"],
                "description": rule["description"],
            })
            continue

        actual = run["current"][setting]
        passed = evaluate_rule(rule, actual)

        if passed is None:
            manual_checks.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "setting": setting,
                "reason": "This check could not be evaluated automatically",
            })
            continue

        if not passed:
            findings.append({
                "rule_id": rule["id"],
                "setting": setting,
                "title": rule["title"],
                "type": "modified",
                "expected": rule["expected"],
                "actual": actual,
                "severity": rule["severity"],
                "description": rule["description"],
            })

    return findings, manual_checks


# ---------------------------------------------------------------------------
# Comparison run construction

def build_run(
    cur_name: str,
    cur_bytes: bytes,
    base_name: str | None = None,
    base_bytes: bytes | None = None,
) -> dict:
    """Parse uploads and prepare a custom or built-in-baseline comparison."""
    if not cur_name:
        raise ConfigError("Please provide a current configuration filename.")

    current, current_kind = parse_config(cur_name, cur_bytes)

    if base_bytes is not None:
        # CUSTOM BASELINE: exact key/value comparison.
        baseline, base_kind = parse_config(base_name or "baseline", base_bytes)
        mode = "custom"
        base_label = base_name or "baseline"
        not_covered = []
        missing = []
        rules = []
        rule_group = None
    else:
        # STANDARD BASELINE: evaluate the selected platform's built-in rules.
        rule_group = select_standard_group(current, current_kind, cur_name)
        rules = STANDARD_SECURITY_BASELINE[rule_group]
        covered_settings = {
            get_rule_setting(rule, rule_group) for rule in rules
        }
        not_covered = [
            key for key in current if key not in covered_settings
        ]
        missing = []
        baseline = {}
        base_kind = "standard"
        mode = "standard"
        base_label = f"Standard Security Baseline ({rule_group})"

    digest_source = (
        cur_bytes + (base_bytes if base_bytes is not None else b"standard")
    )
    digest = hashlib.sha1(digest_source).hexdigest()[:8]

    return {
        "id": f"cfg-{digest}",
        "name": cur_name,
        "kind": current_kind,
        "base_kind": base_kind,
        "mode": mode,
        "base_label": base_label,
        "baseline": baseline,
        "current": current,
        "not_covered": not_covered,
        "missing": missing,
        "rules": rules,
        "rule_group": rule_group,
        "manual_checks": [],
        "last_scan": datetime.now(),
    }


# ---------------------------------------------------------------------------
# Custom baseline comparison

def _norm(value):
    """Stable JSON representation for custom-baseline comparisons."""
    if isinstance(value, list):
        value = sorted(value, key=str)
    return json.dumps(value, sort_keys=True, default=str)


def find_drifts(baseline: dict, current: dict) -> list[dict]:
    """Compare custom baseline vs current -> setting/type/expected/actual."""
    findings = []

    for key, expected in baseline.items():
        if key not in current:
            findings.append({
                "setting": key,
                "type": "removed",
                "expected": expected,
                "actual": None,
            })
        elif _norm(expected) != _norm(current[key]):
            findings.append({
                "setting": key,
                "type": "modified",
                "expected": expected,
                "actual": current[key],
            })

    for key, actual in current.items():
        if key not in baseline:
            findings.append({
                "setting": key,
                "type": "added",
                "expected": None,
                "actual": actual,
            })

    return findings


# ---------------------------------------------------------------------------
# Risk and analysis

def rate_risk(f: dict) -> str:
    if "severity" in f:
        severity = f["severity"]
        if severity in RISK_ORDER and severity != "None":
            return "High" if severity == "Critical" else severity
    return RISK_RULES.get(f["setting"], "Medium")


def overall_risk(findings: list[dict]) -> str:
    if not findings:
        return "None"
    return min(
        (finding["risk"] for finding in findings),
        key=lambda risk: RISK_ORDER.get(risk, RISK_ORDER["Medium"]),
    )


def posture_score(findings: list[dict]) -> int:
    """100 - 15 per High/Critical - 7 per Medium - 2 per Low, floored at 0."""
    return max(
        0,
        100 - sum(PENALTY.get(finding["risk"], 7) for finding in findings),
    )


def analyze(run: dict) -> dict:
    """Analyze either a prepared upload run or a legacy data.py server record.

    Legacy records contain id/name/baseline/current but do not contain the
    newer mode/rules metadata. They are treated as custom-baseline comparisons
    so the existing dashboard and parity tests remain compatible.
    """
    legacy_record = "mode" not in run

    if not legacy_record and run["mode"] == "standard":
        findings, manual_checks = evaluate_standard_rules(run)
    else:
        findings = find_drifts(run["baseline"], run["current"])
        manual_checks = []

    for finding in findings:
        identifier = finding.get("rule_id", finding["setting"])
        finding["id"] = f"{run['id']}::{identifier}"
        finding["server_id"] = run["id"]
        finding["risk"] = rate_risk(finding)

        if legacy_record:
            finding["score"] = legacy_finding_score(
                finding["setting"], finding.get("actual")
            )
        else:
            # Keep a numeric per-finding score available to UI/report callers.
            severity_scores = {
                "Critical": 95,
                "High": 85,
                "Medium": 60,
                "Low": 25,
            }
            finding["score"] = severity_scores.get(
                finding.get("severity"), 60
            )

    findings.sort(
        key=lambda finding: RISK_ORDER.get(
            finding["risk"], RISK_ORDER["Medium"]
        )
    )

    return {
        **run,
        "mode": run.get("mode", "custom"),
        "findings": findings,
        "manual_checks": manual_checks,
        "highest": overall_risk(findings),
        "score": posture_score(findings),
    }


def totals(analyzed: list[dict]) -> dict:
    all_findings = [
        finding
        for server in analyzed
        for finding in server["findings"]
    ]
    counts = {"High": 0, "Medium": 0, "Low": 0}

    for finding in all_findings:
        risk = finding["risk"]
        if risk == "Critical":
            risk = "High"
        if risk in counts:
            counts[risk] += 1

    affected = sum(1 for server in analyzed if server["findings"])
    posture = (
        round(sum(server["score"] for server in analyzed) / len(analyzed))
        if analyzed else 100
    )

    return {
        "all": all_findings,
        "c": counts,
        "affected": affected,
        "healthy": len(analyzed) - affected,
        "total": len(all_findings),
        "posture": posture,
    }


# ---------------------------------------------------------------------------
# Report formatting and exports

def plain(value, present: bool = True) -> str:
    if not present:
        return "not set"
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if isinstance(value, list):
        return "[" + ", ".join(str(item) for item in value) + "]"
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def f_expected(f):
    """Printable expected value of a finding."""
    return plain(f["expected"], f["type"] != "added")


def f_actual(f):
    """Printable actual value of a finding."""
    return plain(f["actual"], f["type"] != "removed")


def summary(f: dict) -> str:
    return f"{label(f['setting'])}: {f_expected(f)} → {f_actual(f)}"


def report_data(analyzed: list[dict], decisions: dict) -> dict:
    totals_data = totals(analyzed)

    return {
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "comparisons": len(analyzed),
            "drifts": totals_data["total"],
            "high": totals_data["c"]["High"],
            "medium": totals_data["c"]["Medium"],
            "low": totals_data["c"]["Low"],
            "postureScore": totals_data["posture"],
        },
        "comparisons": [
            {
                "id": server["id"],
                "currentFile": server["name"],
                "fileType": server["kind"],
                "comparedAgainst": server["base_label"],
                "baselineMode": server["mode"],
                "scannedAt": server["last_scan"].isoformat(timespec="seconds"),
                "riskLevel": server["highest"],
                "score": server["score"],
                "findings": [
                    {
                        "ruleId": finding.get("rule_id"),
                        "title": finding.get("title"),
                        "setting": finding["setting"],
                        "change": finding["type"],
                        "expected": finding["expected"],
                        "actual": finding["actual"],
                        "risk": finding["risk"],
                        "decision": decisions.get(
                            finding["id"],
                            {"status": "Pending"},
                        ),
                    }
                    for finding in server["findings"]
                ],
                "manualChecks": server.get("manual_checks", []),
            }
            for server in analyzed
        ],
    }


def report_csv(analyzed: list[dict], decisions: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
    writer.writerow([
        "file",
        "compared_against",
        "setting",
        "change",
        "expected",
        "actual",
        "risk",
        "status",
        "decided_by",
        "decided_at",
        "note",
    ])

    for server in analyzed:
        for finding in server["findings"]:
            decision = decisions.get(finding["id"], {})
            writer.writerow([
                server["name"],
                server["base_label"],
                finding["setting"],
                finding["type"],
                f_expected(finding),
                f_actual(finding),
                finding["risk"],
                decision.get("status", "Pending"),
                decision.get("by", ""),
                decision.get("at", ""),
                decision.get("note", ""),
            ])

    return buffer.getvalue()
