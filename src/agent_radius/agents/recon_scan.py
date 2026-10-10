"""Local credential discovery. Presence and names only, never secret values.

How values are handled: files are parsed in memory. For every key that can
hold a secret, the value is dropped the moment the key name is recorded. The
only value-derived datum kept is a salted SHA-256 fingerprint (16 hex chars)
of an access key ID, used to match the key to an IAM user offline. The
secret access key and session token are never read into any structure that
outlives the parse.

Paths are injectable (``ReconPaths``) so tests run against ``tmp_path`` and
never touch the real home directory.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_radius.security.redact import find_secrets
from agent_radius.snapshot.model import LocalCredential

_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_FINGERPRINT_SALT = b"agent-radius:v1:"

SECRET_KEY_NAMES = {
    "aws_secret_access_key",
    "aws_session_token",
    "aws_security_token",
}
STATIC_KEY_NAMES = {"aws_access_key_id", "aws_secret_access_key"}
AWS_ENV_NAMES = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
}


def fingerprint_access_key_id(key_id: str) -> str:
    return hashlib.sha256(_FINGERPRINT_SALT + key_id.encode("utf-8")).hexdigest()[:16]


@dataclass
class ReconPaths:
    home: Path
    cwd: Path
    env: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_system(cls) -> ReconPaths:
        """Real paths. Only the live mode uses this."""
        return cls(home=Path.home(), cwd=Path.cwd(), env=dict(os.environ))

    def display(self, path: Path) -> str:
        try:
            return "~/" + str(path.relative_to(self.home))
        except ValueError:
            try:
                return "./" + str(path.relative_to(self.cwd))
            except ValueError:
                return str(path)

    def aws_config(self) -> Path:
        override = self.env.get("AWS_CONFIG_FILE")
        return Path(override).expanduser() if override else self.home / ".aws" / "config"

    def aws_credentials(self) -> Path:
        override = self.env.get("AWS_SHARED_CREDENTIALS_FILE")
        return Path(override).expanduser() if override else self.home / ".aws" / "credentials"

    def gcloud_adc(self) -> list[Path]:
        paths = [self.home / ".config" / "gcloud" / "application_default_credentials.json"]
        override = self.env.get("GOOGLE_APPLICATION_CREDENTIALS")
        if override:
            paths.append(Path(override).expanduser())
        return paths

    def agent_configs(self) -> list[tuple[str, Path]]:
        """(source_type, path) for MCP and coding-agent config files."""
        h, c = self.home, self.cwd
        return [
            ("mcp_config", c / ".mcp.json"),
            ("mcp_config", c / ".cursor" / "mcp.json"),
            ("mcp_config", c / ".vscode" / "mcp.json"),
            ("mcp_config", h / ".cursor" / "mcp.json"),
            ("mcp_config", h / ".codeium" / "windsurf" / "mcp_config.json"),
            ("mcp_config", h / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
            ("mcp_config", h / ".config" / "Claude" / "claude_desktop_config.json"),
            ("agent_config", h / ".claude.json"),
            ("agent_config", h / ".claude" / "settings.json"),
            ("agent_config", c / ".claude" / "settings.json"),
            ("agent_config", c / ".claude" / "settings.local.json"),
        ]

    def all_candidate_paths(self) -> list[str]:
        out = [self.display(self.aws_config()), self.display(self.aws_credentials())]
        out += [self.display(p) for p in self.gcloud_adc()]
        out += [self.display(p) for _, p in self.agent_configs()]
        return out


@dataclass
class ReconResult:
    credentials: list[LocalCredential]
    fingerprints: dict[str, str]  # credential id -> access key fingerprint (never emitted)
    scanned: list[str]
    errors: list[str]


def _cred_id(source_type: str, display: str, label: str) -> str:
    return f"cred:{source_type}:{display}#{label}"


def _scan_ini(path: Path, display: str, source_type: str, is_config: bool) -> tuple[list[LocalCredential], dict[str, str]]:
    parser = configparser.RawConfigParser(strict=False)
    with path.open(encoding="utf-8", errors="replace") as fh:
        parser.read_file(fh)
    creds: list[LocalCredential] = []
    fps: dict[str, str] = {}
    for section in parser.sections():
        if is_config:
            if section.startswith("profile "):
                profile = section[len("profile ") :].strip()
            elif section == "default":
                profile = "default"
            else:
                # sso-session and services sections carry no credentials.
                continue
        else:
            profile = section
        keys = {k.lower() for k in parser.options(section)}
        key_names = sorted(keys & (STATIC_KEY_NAMES | SECRET_KEY_NAMES | {"role_arn", "source_profile", "credential_process", "sso_start_url", "sso_session", "web_identity_token_file"}))
        if not key_names:
            continue
        role_arn = parser.get(section, "role_arn") if "role_arn" in keys else None
        if role_arn and not role_arn.startswith("arn:"):
            role_arn = None
        detail_bits = []
        if "source_profile" in keys:
            detail_bits.append(f"source_profile={parser.get(section, 'source_profile').strip()}")
        if "credential_process" in keys:
            detail_bits.append("credential_process present (command not recorded)")
        if "sso_start_url" in keys or "sso_session" in keys:
            detail_bits.append("SSO profile")
        cid = _cred_id(source_type, display, profile)
        if "aws_access_key_id" in keys:
            key_id = parser.get(section, "aws_access_key_id").strip()
            if _KEY_ID_RE.fullmatch(key_id):
                fps[cid] = fingerprint_access_key_id(key_id)
        creds.append(
            LocalCredential(
                id=cid,
                source_type=source_type,
                path=display,
                profile_name=profile,
                principal_arn=role_arn,
                has_static_keys=bool(keys & STATIC_KEY_NAMES),
                key_names=key_names,
                detail="; ".join(detail_bits),
                mapped_via="role_arn" if role_arn else None,
            )
        )
    return creds, fps


def _walk_json(node: Any, trail: str, found: list[tuple[str, dict[str, Any], list[Any]]]) -> None:
    """Collect (trail, env, args) for every MCP server and every env block.

    Handles ``mcpServers`` (Claude, Cursor, Windsurf), ``servers`` (VS Code)
    and bare ``env`` blocks (Claude Code settings), at any nesting depth.
    """
    if isinstance(node, dict):
        for server_key in ("mcpServers", "servers"):
            servers = node.get(server_key)
            if not isinstance(servers, dict):
                continue
            for name, spec in servers.items():
                if not isinstance(spec, dict):
                    continue
                if server_key == "servers" and not ({"command", "url", "args", "env"} & set(spec)):
                    continue
                env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
                args = spec.get("args") if isinstance(spec.get("args"), list) else []
                found.append((f"{trail}{server_key}.{name}", env, args))
        env = node.get("env")
        if isinstance(env, dict):
            found.append((f"{trail}env", env, []))
        for key, value in node.items():
            if key in ("mcpServers", "servers", "env"):
                continue
            if isinstance(value, (dict, list)):
                _walk_json(value, f"{trail}{key}.", found)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _walk_json(value, f"{trail}{i}.", found)


def _scan_agent_config(path: Path, display: str, source_type: str) -> tuple[list[LocalCredential], dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    blocks: list[tuple[str, dict[str, Any], list[Any]]] = []
    _walk_json(data, "", blocks)
    creds: list[LocalCredential] = []
    fps: dict[str, str] = {}
    for trail, env, args in blocks:
        names = sorted(k for k in env if k.upper() in AWS_ENV_NAMES)
        profile = None
        fp = None
        for k in names:
            if k.upper() in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE") and isinstance(env[k], str):
                profile = env[k].strip()
            if k.upper() == "AWS_ACCESS_KEY_ID" and isinstance(env[k], str) and _KEY_ID_RE.fullmatch(env[k].strip()):
                fp = fingerprint_access_key_id(env[k].strip())
        arg_text = " ".join(str(a) for a in args)
        if profile is None:
            m = re.search(r"--profile[= ]+([A-Za-z0-9_.@-]+)", arg_text)
            if m:
                profile = m.group(1)
        embedded_key = _KEY_ID_RE.search(arg_text)
        if embedded_key and fp is None:
            fp = fingerprint_access_key_id(embedded_key.group(0))
        if not names and profile is None and embedded_key is None:
            continue
        key_names = list(names)
        if embedded_key:
            key_names.append("access key ID in args")
        has_static = any(k.upper() in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY") for k in names) or bool(embedded_key)
        cid = _cred_id(source_type, display, trail)
        if fp:
            fps[cid] = fp
        creds.append(
            LocalCredential(
                id=cid,
                source_type=source_type,
                path=display,
                profile_name=profile,
                has_static_keys=has_static,
                key_names=key_names,
                detail=trail,
            )
        )
    return creds, fps


def scan_local(paths: ReconPaths) -> ReconResult:
    creds: list[LocalCredential] = []
    fps: dict[str, str] = {}
    scanned: list[str] = []
    errors: list[str] = []

    def attempt(fn: Callable[[], tuple[list[LocalCredential], dict[str, str]]], display: str) -> None:
        scanned.append(display)
        try:
            c, f = fn()
        except (OSError, ValueError, configparser.Error) as exc:
            errors.append(f"{display}: could not parse ({type(exc).__name__})")
            return
        creds.extend(c)
        fps.update(f)

    cfg = paths.aws_config()
    if cfg.is_file():
        d = paths.display(cfg)
        attempt(lambda: _scan_ini(cfg, d, "aws_profile", True), d)
    cred_file = paths.aws_credentials()
    if cred_file.is_file():
        d = paths.display(cred_file)
        attempt(lambda: _scan_ini(cred_file, d, "aws_profile", False), d)
    for adc in paths.gcloud_adc():
        if adc.is_file():
            d = paths.display(adc)
            scanned.append(d)
            creds.append(
                LocalCredential(
                    id=_cred_id("gcloud_adc", d, "adc"),
                    source_type="gcloud_adc",
                    path=d,
                    detail="Google application default credentials file is present (GCP is not analysed in v1)",
                )
            )
    for source_type, p in paths.agent_configs():
        if p.is_file():
            d = paths.display(p)
            attempt(lambda p=p, d=d, st=source_type: _scan_agent_config(p, d, st), d)

    env_names = sorted(k for k in paths.env if k.upper() in AWS_ENV_NAMES)
    if env_names:
        profile = paths.env.get("AWS_PROFILE") or paths.env.get("AWS_DEFAULT_PROFILE")
        cid = _cred_id("env_var", "environment", "AWS_*")
        key_id = paths.env.get("AWS_ACCESS_KEY_ID", "")
        if _KEY_ID_RE.fullmatch(key_id.strip()):
            fps[cid] = fingerprint_access_key_id(key_id.strip())
        creds.append(
            LocalCredential(
                id=cid,
                source_type="env_var",
                path="environment",
                profile_name=profile,
                has_static_keys=any(n in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY") for n in env_names),
                key_names=env_names,
                detail="variables inherited by any agent process started from this shell",
            )
        )

    # Backstop: no record may carry a secret-shaped value.
    for c in creds:
        blob = json.dumps(c.__dict__, default=str)
        hits = find_secrets(blob)
        if hits:
            raise RuntimeError(f"recon bug: secret-shaped value in credential record ({hits})")
    return ReconResult(creds, fps, scanned, errors)
