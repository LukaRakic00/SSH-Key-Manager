#!/usr/bin/env python3
"""SSH Key Manager for Windows.

Interactive, standard-library-only utility that:

* generates SSH keys with the Windows OpenSSH client (``ssh-keygen``),
* maintains clearly marked, isolated blocks in ``~/.ssh/config``,
* registers GitHub *authentication* keys through the official GitHub CLI (``gh``),
* tests SSH connectivity without running remote commands.

Private key contents are never read, printed, logged or transmitted.
All messages shown to the user are in Serbian (Latin script); code comments
are in English for maintainers.

Run ``python ssh_manager.py`` for the interactive menu or
``python ssh_manager.py --help`` for command-line options.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # pragma: no cover - guard for old interpreters
    sys.stderr.write(
        "ssh_manager.py zahteva Python 3.11 ili noviji.\n"
        "Instalirajte ga komandom: winget install --id Python.Python.3.13\n"
    )
    raise SystemExit(1)

import argparse
import contextlib
import ipaddress
import os
import platform
import queue
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Callable, Mapping, Sequence, TextIO, TypeVar

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

GITHUB_HOST = "github.com"
GITHUB_SSH_USER = "git"
GITHUB_KEYS_URL = "https://github.com/settings/keys"
GITHUB_FINGERPRINTS_URL = (
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
    "githubs-ssh-key-fingerprints"
)
GITHUB_HOST_KEY_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("ED25519", "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"),
    ("ECDSA", "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"),
    ("RSA", "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"),
)
# OAuth scopes that allow creating SSH authentication keys. write:public_key is
# the least-privileged one (create, list, view); admin:public_key also allows deletion.
GITHUB_KEY_SCOPES = frozenset({"write:public_key", "admin:public_key"})
GITHUB_REFRESH_SCOPE = "write:public_key"
# Aliases that would silently change every existing connection to GitHub.
GITHUB_RESERVED_ALIASES = frozenset({"github.com", "ssh.github.com", "gist.github.com"})
ENV_TOKEN_SOURCES = frozenset(
    {"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}
)

CONNECT_TIMEOUT_SECONDS = 15
INTERACTIVE_TEST_TIMEOUT_SECONDS = 180
COMMAND_TIMEOUT_SECONDS = 60
MAX_NAME_LENGTH = 64

GH_LOGIN_COMMAND = (
    "gh auth login --hostname github.com --git-protocol ssh --web --skip-ssh-key"
)
GH_REFRESH_COMMAND = f"gh auth refresh --hostname github.com --scopes {GITHUB_REFRESH_SCOPE}"

OPENSSH_INSTALL_HINT = (
    "Instalirajte Windows OpenSSH Client:\n"
    "  Settings > System > Optional features > View features > 'OpenSSH Client'\n"
    "  ili u PowerShell-u pokrenutom kao administrator:\n"
    "  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0\n"
    "Zatim otvorite novi terminal."
)
GH_INSTALL_HINT = (
    "Instalirajte GitHub CLI:\n"
    "  winget install --id GitHub.cli\n"
    "Zatim zatvorite i ponovo otvorite terminal da bi se učitao ažurirani PATH."
)
GIT_INSTALL_HINT = "Instalirajte Git for Windows:\n  winget install --id Git.Git"
AGENT_NOTE = (
    "Opcija 'AddKeysToAgent yes' dodaje ključ samo u ssh-agent koji je već pokrenut.\n"
    "Ona ne pokreće agenta. Na Windowsu je servis 'OpenSSH Authentication Agent'\n"
    "podrazumevano isključen. Da biste ga uključili, u PowerShell-u pokrenutom\n"
    "kao administrator izvršite:\n"
    "  Get-Service ssh-agent | Set-Service -StartupType Automatic\n"
    "  Start-Service ssh-agent"
)

YES_ANSWERS = frozenset({"d", "da", "y", "yes"})
NO_ANSWERS = frozenset({"n", "ne", "no"})

T = TypeVar("T")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class SSHManagerError(Exception):
    """Base class for expected, user-facing errors."""


class ValidationError(SSHManagerError):
    """Invalid user input."""


class ConfigError(SSHManagerError):
    """Problem reading, parsing or writing the SSH config."""


class CommandError(SSHManagerError):
    """An external command could not be run or failed."""


class KeyExistsError(SSHManagerError):
    """A key file with the requested name already exists."""


class UserAbort(Exception):
    """The user cancelled the current operation (or input ended)."""


# --------------------------------------------------------------------------- #
# Redaction helpers
# --------------------------------------------------------------------------- #

_SECRET_PATTERNS = (
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
        re.S,
    ),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,})"),
)


def redact(text: str) -> str:
    """Remove anything that looks like a private key or a GitHub token."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[UKLONJENO]", text)
    return text


def excerpt(text: str, max_lines: int = 8) -> str:
    """Return a short, redacted excerpt of command output for error messages."""
    lines = [line.rstrip() for line in redact(text).splitlines() if line.strip()]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["..."]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ALIAS_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_HOST_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._@-]{0,63}$")
_GH_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_GH_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)
# Files OpenSSH treats specially. Default identity names are reserved because
# ssh offers them to *every* host, which would change unrelated connections.
RESERVED_SSH_FILE_NAMES = frozenset(
    {
        "config",
        "known_hosts",
        "known_hosts.old",
        "authorized_keys",
        "authorized_keys2",
        "environment",
        "rc",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ecdsa_sk",
        "id_ed25519",
        "id_ed25519_sk",
        "id_xmss",
    }
)


def validate_key_name(raw: str) -> str:
    """Validate a key name, which is also used as the file name and SSH host alias."""
    name = raw.strip()
    if not name:
        raise ValidationError("Naziv ne sme biti prazan.")
    if len(name) > MAX_NAME_LENGTH:
        raise ValidationError(f"Naziv može imati najviše {MAX_NAME_LENGTH} znakova.")
    if any(sep in name for sep in ("/", "\\", ":")) or ".." in name:
        raise ValidationError("Naziv ne sme sadržati separatore putanje ('/', '\\'), ':' ni '..'.")
    if not _NAME_RE.fullmatch(name):
        raise ValidationError(
            "Koristite samo slova bez dijakritika (a-z, A-Z), cifre, '.', '_' i '-'; "
            "naziv mora počinjati slovom ili cifrom."
        )
    if name.endswith("."):
        raise ValidationError("Naziv ne sme da se završava tačkom.")
    lower = name.lower()
    if lower.endswith(".pub"):
        raise ValidationError("Naziv ne sme da se završava sa '.pub'.")
    if lower.split(".")[0] in WINDOWS_RESERVED_NAMES:
        raise ValidationError(f"'{name}' je rezervisan naziv uređaja na Windowsu.")
    if lower in RESERVED_SSH_FILE_NAMES:
        raise ValidationError(
            f"'{name}' je rezervisan za OpenSSH (config ili podrazumevani fajl ključa). "
            "Izaberite drugi naziv."
        )
    if lower in GITHUB_RESERVED_ALIASES:
        raise ValidationError(
            f"'{name}' bi promenio svaku SSH vezu ka GitHub-u. "
            "Koristite poseban alias, na primer 'github-work'."
        )
    return name


def validate_alias_token(raw: str) -> str:
    """Validate an existing SSH host alias typed by the user (for testing)."""
    alias = raw.strip()
    if not _ALIAS_TOKEN_RE.fullmatch(alias) or ".." in alias:
        raise ValidationError(
            "Unesite običan host alias (slova, cifre, '.', '_', '-'; bez razmaka i džokera)."
        )
    return alias


def suggest_github_name(name: str) -> str:
    """Suggest a GitHub-specific alias without ever doubling the prefix."""
    if name.lower().startswith("github"):
        return name
    return f"github-{name}"


def validate_hostname(raw: str) -> str:
    """Validate a DNS name, IPv4 address or IPv6 address."""
    host = raw.strip()
    if not host:
        raise ValidationError("Adresa servera ne sme biti prazna.")
    if "%" in host:
        raise ValidationError("IPv6 adrese sa zonom i znak '%' nisu podržani.")
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(host):
        raise ValidationError(
            "Unesite ispravno ime hosta (na primer server.example.com) ili IP adresu."
        )
    return host


def validate_username(raw: str) -> str:
    """Validate an SSH login name."""
    user = raw.strip()
    if not _USERNAME_RE.fullmatch(user):
        raise ValidationError(
            "Unesite ispravno korisničko ime (slova, cifre, '.', '_', '-', '@'; "
            "ne sme počinjati sa '-'; najviše 64 znaka)."
        )
    return user


def validate_port(raw: str) -> int | None:
    """Validate an optional TCP port. Empty input means the default (22)."""
    value = raw.strip()
    if not value:
        return None
    if not value.isdigit():
        raise ValidationError("Port mora biti broj od 1 do 65535.")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValidationError("Port mora biti broj od 1 do 65535.")
    return port


def parse_owner_repo(raw: str) -> tuple[str, str]:
    """Parse 'OWNER/REPOSITORY' (optionally ending in .git)."""
    value = raw.strip()
    if value.endswith(".git"):
        value = value[:-4]
    parts = value.split("/")
    if len(parts) != 2:
        raise ValidationError("Koristite format OWNER/REPOSITORY.")
    owner, repo = parts
    if not _GH_OWNER_RE.fullmatch(owner):
        raise ValidationError(f"'{owner}' nije ispravno ime GitHub vlasnika (OWNER).")
    if not _GH_REPO_RE.fullmatch(repo) or repo in {".", ".."}:
        raise ValidationError(f"'{repo}' nije ispravno ime GitHub repozitorijuma (REPOSITORY).")
    return owner, repo


def github_remote_url(alias: str, owner: str, repo: str) -> str:
    """Build the SSH remote URL that uses the exact alias from the SSH config."""
    validate_alias_token(alias)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"git@{alias}:{owner}/{repo}.git"


# --------------------------------------------------------------------------- #
# Running external commands
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return "\n".join(part for part in (self.stdout, self.stderr) if part).strip()


@dataclass(frozen=True)
class StreamResult:
    returncode: int | None
    lines: list[str]
    stopped_early: bool = False
    timed_out: bool = False

    @property
    def output(self) -> str:
        return "\n".join(self.lines)


def _display_command(argv: Sequence[str]) -> str:
    return " ".join([Path(argv[0]).name, *argv[1:]]) if argv else ""


def _check_argv(args: Sequence[str | os.PathLike[str]]) -> list[str]:
    argv = [os.fspath(arg) for arg in args]
    if not argv:
        raise CommandError("Komanda nije zadata.")
    for arg in argv:
        if not isinstance(arg, str) or "\x00" in arg:
            raise CommandError("Komanda sa neispravnim argumentom neće biti pokrenuta.")
    return argv


class CommandRunner:
    """Runs programs with argument lists only (never through a shell)."""

    def run(
        self,
        args: Sequence[str | os.PathLike[str]],
        *,
        interactive: bool = False,
        timeout: float | None = COMMAND_TIMEOUT_SECONDS,
        env_overrides: Mapping[str, str] | None = None,
    ) -> CommandResult:
        argv = _check_argv(args)
        env = {**os.environ, **env_overrides} if env_overrides else None
        try:
            if interactive:
                # The user talks to the program directly (passphrases, browser login).
                completed = subprocess.run(argv, check=False, env=env)
                return CommandResult(tuple(argv), completed.returncode)
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                env=env,
            )
        except FileNotFoundError as exc:
            raise CommandError(f"Program nije pronađen: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandError(
                f"Komanda '{_display_command(argv)}' se nije završila za {timeout} sekundi."
            ) from exc
        except OSError as exc:
            raise CommandError(f"Nije moguće pokrenuti '{_display_command(argv)}': {exc}") from exc
        return CommandResult(
            tuple(argv), completed.returncode, completed.stdout or "", completed.stderr or ""
        )

    def stream(
        self,
        args: Sequence[str | os.PathLike[str]],
        *,
        on_line: Callable[[str], None],
        stop_when: Callable[[str], bool] | None = None,
        timeout: float = INTERACTIVE_TEST_TIMEOUT_SECONDS,
    ) -> StreamResult:
        """Run a program, echoing its combined output line by line.

        stdin stays attached to the console so ssh can ask for passphrases and
        host-key confirmation. If ``stop_when`` matches a line, the process is
        terminated (used to disconnect right after authentication succeeds).
        """
        argv = _check_argv(args)
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise CommandError(f"Program nije pronađen: {argv[0]}") from exc
        except OSError as exc:
            raise CommandError(f"Nije moguće pokrenuti '{_display_command(argv)}': {exc}") from exc

        lines_queue: queue.Queue[str | None] = queue.Queue()

        def reader() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                lines_queue.put(line)
            lines_queue.put(None)

        reader_thread = threading.Thread(target=reader, daemon=True)
        reader_thread.start()
        deadline = time.monotonic() + timeout
        lines: list[str] = []
        stopped = timed_out = False
        try:
            while True:
                try:
                    item = lines_queue.get(timeout=0.2)
                except queue.Empty:
                    if time.monotonic() > deadline:
                        timed_out = True
                        proc.terminate()
                        break
                    continue
                if item is None:
                    break
                line = item.rstrip("\r\n")
                lines.append(line)
                on_line(line)
                if stop_when is not None and stop_when(line):
                    stopped = True
                    proc.terminate()
                    break
        except KeyboardInterrupt:
            proc.terminate()
            raise
        finally:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            reader_thread.join(timeout=2)
            if proc.stdout is not None and not reader_thread.is_alive():
                with contextlib.suppress(OSError, ValueError):
                    proc.stdout.close()
        return StreamResult(proc.returncode, lines, stopped, timed_out)


# --------------------------------------------------------------------------- #
# Tool discovery
# --------------------------------------------------------------------------- #


def _windows_openssh_dirs() -> list[Path]:
    if os.name != "nt":
        return []
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    # Sysnative is only visible to 32-bit processes on 64-bit Windows.
    return [root / "Sysnative" / "OpenSSH", root / "System32" / "OpenSSH"]


def _gh_fallback_dirs() -> list[Path]:
    if os.name != "nt":
        return []
    dirs = []
    for var, sub in (("ProgramFiles", "GitHub CLI"), ("LOCALAPPDATA", r"Programs\GitHub CLI")):
        base = os.environ.get(var)
        if base:
            dirs.append(Path(base) / sub)
    return dirs


def find_tool(
    name: str, preferred_dirs: Sequence[Path] = (), fallback_dirs: Sequence[Path] = ()
) -> str | None:
    exe = f"{name}.exe" if os.name == "nt" else name
    for directory in preferred_dirs:
        candidate = directory / exe
        if candidate.is_file():
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    for directory in fallback_dirs:
        candidate = directory / exe
        if candidate.is_file():
            return str(candidate)
    return None


@dataclass(frozen=True)
class Tools:
    ssh: str | None
    ssh_keygen: str | None
    ssh_add: str | None
    gh: str | None
    git: str | None
    icacls: str | None = None

    @classmethod
    def discover(cls) -> Tools:
        # Prefer the Windows OpenSSH client so keys, config validation and the
        # Windows ssh-agent service all use the same implementation, even when
        # Git Bash puts its own ssh first on PATH.
        openssh = _windows_openssh_dirs()
        return cls(
            ssh=find_tool("ssh", openssh),
            ssh_keygen=find_tool("ssh-keygen", openssh),
            ssh_add=find_tool("ssh-add", openssh),
            gh=find_tool("gh", fallback_dirs=_gh_fallback_dirs()),
            git=find_tool("git"),
            icacls=find_tool("icacls") if os.name == "nt" else None,
        )


# --------------------------------------------------------------------------- #
# SSH config parsing and editing
# --------------------------------------------------------------------------- #

# The marker format is parsed by this tool; do not translate or change it.
BLOCK_BEGIN_PREFIX = "# BEGIN SSH-MANAGER "
BLOCK_END_PREFIX = "# END SSH-MANAGER "
_BEGIN_RE = re.compile(r"^\s*# BEGIN SSH-MANAGER (?P<alias>\S+) kind=(?P<kind>\S+)\s*$")
_END_RE = re.compile(r"^\s*# END SSH-MANAGER (?P<alias>\S+)\s*$")
_KEYWORD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*)(?:(?:\s*=\s*|\s+)(.*))?$")


class HostKind(StrEnum):
    GITHUB = "github"
    SERVER = "server"


@dataclass(frozen=True)
class HostSpec:
    """Desired content of one managed Host block."""

    alias: str
    kind: HostKind
    hostname: str
    user: str
    identity_file: str
    port: int | None = None

    def render(self, created: str) -> list[str]:
        lines = [
            f"{BLOCK_BEGIN_PREFIX}{self.alias} kind={self.kind}",
            f"# Upravlja ssh_manager.py ({created}). Ne menjajte redove sa BEGIN/END oznakama.",
            f"Host {self.alias}",
            f"    HostName {self.hostname}",
            f"    User {self.user}",
        ]
        if self.port is not None:
            lines.append(f"    Port {self.port}")
        lines += [
            f"    IdentityFile {self.identity_file}",
            "    IdentitiesOnly yes",
            "    AddKeysToAgent yes",
            f"{BLOCK_END_PREFIX}{self.alias}",
        ]
        return lines


@dataclass
class ManagedBlock:
    alias: str
    kind: str
    start: int  # 0-based index of the BEGIN marker line
    end: int  # 0-based index of the END marker line
    options: dict[str, str] = field(default_factory=dict)


@dataclass
class HostLine:
    index: int  # 0-based line index
    patterns: list[str]
    managed_alias: str | None


@dataclass
class AliasConflicts:
    managed: ManagedBlock | None = None
    unmanaged_lines: list[int] = field(default_factory=list)  # 1-based line numbers
    wildcard_patterns: list[str] = field(default_factory=list)


def split_config_args(text: str) -> list[str]:
    """Split ssh_config arguments, honouring double quotes and trailing comments."""
    tokens: list[str] = []
    current: list[str] = []
    in_quotes = has_token = False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
            has_token = True
            continue
        if ch.isspace() and not in_quotes:
            if has_token:
                tokens.append("".join(current))
                current, has_token = [], False
            continue
        if ch == "#" and not in_quotes and not has_token:
            break
        current.append(ch)
        has_token = True
    if has_token:
        tokens.append("".join(current))
    return tokens


def host_pattern_matches(pattern: str, host: str) -> bool:
    """ssh_config style matching ('*' and '?' wildcards, case-insensitive)."""
    regex = "".join(
        ".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern
    )
    return re.fullmatch(regex, host, re.IGNORECASE) is not None


def _split_lines(text: str) -> list[str]:
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def _keyword(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = _KEYWORD_RE.match(stripped)
    if not match:
        return None
    return match.group(1).lower(), (match.group(2) or "")


class SSHConfigDocument:
    """An SSH config file kept as exact original lines (including line endings)."""

    def __init__(self, text: str = "", *, bom: bool = False) -> None:
        self.bom = bom
        self.newline = "\r\n" if "\r\n" in text else "\n"
        self._lines = _split_lines(text)
        self._blocks = self._parse_blocks()

    @classmethod
    def from_bytes(cls, data: bytes) -> SSHConfigDocument:
        bom = data.startswith(b"\xef\xbb\xbf")
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ConfigError(
                "SSH config nije ispravan UTF-8 tekst, pa neće biti menjan."
            ) from exc
        return cls(text, bom=bom)

    @property
    def text(self) -> str:
        return "".join(self._lines)

    def to_bytes(self) -> bytes:
        return (b"\xef\xbb\xbf" if self.bom else b"") + self.text.encode("utf-8")

    def _content(self, index: int) -> str:
        return self._lines[index].rstrip("\r\n")

    def _parse_blocks(self) -> list[ManagedBlock]:
        blocks: list[ManagedBlock] = []
        current: ManagedBlock | None = None
        for index in range(len(self._lines)):
            content = self._content(index)
            begin, end = _BEGIN_RE.match(content), _END_RE.match(content)
            if begin:
                if current is not None:
                    raise ConfigError(
                        f"SSH config, red {index + 1}: upravljani blok '{begin['alias']}' počinje "
                        f"unutar bloka '{current.alias}'. Ispravite oznake ručno."
                    )
                current = ManagedBlock(begin["alias"], begin["kind"], index, -1)
            elif end:
                if current is None or end["alias"] != current.alias:
                    raise ConfigError(
                        f"SSH config, red {index + 1}: neočekivana završna oznaka za "
                        f"'{end['alias']}'. Ispravite oznake ručno."
                    )
                current.end = index
                blocks.append(current)
                current = None
            elif current is not None:
                parsed = _keyword(content)
                if parsed and parsed[0] != "host":
                    args = split_config_args(parsed[1])
                    current.options.setdefault(parsed[0], args[0] if args else "")
        if current is not None:
            raise ConfigError(
                f"SSH config, red {current.start + 1}: upravljani blok '{current.alias}' nema "
                "završnu oznaku. Ispravite oznake ručno."
            )
        return blocks

    def managed_blocks(self) -> list[ManagedBlock]:
        return list(self._blocks)

    def managed_block(self, alias: str) -> ManagedBlock | None:
        for block in self._blocks:
            if block.alias.casefold() == alias.casefold():
                return block
        return None

    def _block_at(self, index: int) -> ManagedBlock | None:
        for block in self._blocks:
            if block.start <= index <= block.end:
                return block
        return None

    def host_lines(self) -> list[HostLine]:
        result = []
        for index in range(len(self._lines)):
            parsed = _keyword(self._content(index))
            if parsed and parsed[0] == "host":
                block = self._block_at(index)
                result.append(
                    HostLine(index, split_config_args(parsed[1]), block.alias if block else None)
                )
        return result

    def unmanaged_aliases(self) -> list[str]:
        names: list[str] = []
        for host in self.host_lines():
            if host.managed_alias is None:
                names.extend(host.patterns)
        return names

    def find_alias_conflicts(self, alias: str) -> AliasConflicts:
        conflicts = AliasConflicts(managed=self.managed_block(alias))
        wanted = alias.casefold()
        for host in self.host_lines():
            for pattern in host.patterns:
                if pattern.startswith("!"):
                    continue
                if pattern.casefold() == wanted:
                    if host.managed_alias is None or host.managed_alias.casefold() != wanted:
                        conflicts.unmanaged_lines.append(host.index + 1)
                elif (
                    pattern != "*"
                    and any(ch in pattern for ch in "*?")
                    and host_pattern_matches(pattern, alias)
                ):
                    conflicts.wildcard_patterns.append(pattern)
        return conflicts

    def insertion_index(self) -> int:
        """Index before the first Host/Match line, so the new block takes precedence.

        ssh uses the first value it finds for most options, so a block placed
        after e.g. ``Host *`` with ``User`` could be overridden.
        """
        for index in range(len(self._lines)):
            parsed = _keyword(self._content(index))
            if not parsed or parsed[0] not in ("host", "match"):
                continue
            block = self._block_at(index)
            position = block.start if block else index
            # Keep comments that directly describe the following entry attached to it.
            while position > 0:
                previous = self._content(position - 1).strip()
                if (
                    previous.startswith("#")
                    and not _BEGIN_RE.match(previous)
                    and not _END_RE.match(previous)
                    and self._block_at(position - 1) is None
                ):
                    position -= 1
                else:
                    break
            return position
        return len(self._lines)

    def _rendered(self, spec: HostSpec, created: str) -> list[str]:
        return [line + self.newline for line in spec.render(created)]

    def with_block_added(self, spec: HostSpec, created: str) -> SSHConfigDocument:
        if self.managed_block(spec.alias) is not None:
            raise ConfigError(f"Upravljani blok za '{spec.alias}' već postoji.")
        index = self.insertion_index()
        before, after = list(self._lines[:index]), list(self._lines[index:])
        if before and not before[-1].endswith("\n"):
            before[-1] += self.newline
        pieces = before
        if before and before[-1].strip():
            pieces.append(self.newline)
        pieces += self._rendered(spec, created)
        if after and after[0].strip():
            pieces.append(self.newline)
        pieces += after
        return SSHConfigDocument("".join(pieces), bom=self.bom)

    def with_block_replaced(self, spec: HostSpec, created: str) -> SSHConfigDocument:
        block = self.managed_block(spec.alias)
        if block is None:
            raise ConfigError(f"Upravljani blok za '{spec.alias}' ne postoji.")
        new_lines = self._rendered(spec, created)
        if not self._lines[block.end].endswith("\n"):
            new_lines[-1] = new_lines[-1].rstrip("\r\n")
        lines = self._lines[: block.start] + new_lines + self._lines[block.end + 1 :]
        return SSHConfigDocument("".join(lines), bom=self.bom)


def identity_file_for(key_path: Path, home: Path) -> str:
    """Return the IdentityFile value, using '~' when the key is under the home directory."""
    try:
        value = "~/" + key_path.relative_to(home).as_posix()
    except ValueError:
        value = key_path.as_posix()
    if any(ch.isspace() for ch in value):
        value = f'"{value}"'
    return value


def expand_identity_path(value: str, home: Path) -> Path:
    value = value.strip().strip('"')
    if value == "~":
        return home
    if value.startswith(("~/", "~\\")):
        return home / value[2:]
    return Path(value)


def _normalize_path(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def parse_ssh_g_output(output: str) -> dict[str, list[str]]:
    options: dict[str, list[str]] = {}
    for line in output.splitlines():
        key, _, value = line.strip().partition(" ")
        if key:
            options.setdefault(key.lower(), []).append(value.strip())
    return options


def compare_resolved(spec: HostSpec, options: Mapping[str, list[str]], home: Path) -> list[str]:
    """Compare `ssh -G` output with what the managed block should produce."""
    problems = []

    def first(key: str) -> str:
        values = options.get(key) or [""]
        return values[0]

    if first("hostname").casefold() != spec.hostname.casefold():
        problems.append(f"Efektivni HostName je '{first('hostname')}' umesto '{spec.hostname}'.")
    if first("user") != spec.user:
        problems.append(f"Efektivni User je '{first('user')}' umesto '{spec.user}'.")
    expected_port = str(spec.port or 22)
    if first("port") != expected_port:
        problems.append(f"Efektivni Port je '{first('port')}' umesto '{expected_port}'.")
    expected_key = _normalize_path(expand_identity_path(spec.identity_file, home))
    resolved = [_normalize_path(expand_identity_path(v, home)) for v in options.get("identityfile", [])]
    if expected_key not in resolved:
        problems.append(f"IdentityFile {spec.identity_file} se ne koristi za ovaj alias.")
    if first("identitiesonly").lower() != "yes":
        problems.append("IdentitiesOnly nije 'yes' za ovaj alias.")
    return problems


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write via a temporary file and atomic rename; the original survives failures."""
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def create_backup(path: Path) -> Path:
    """Copy ``path`` to a new, never-overwritten timestamped backup file."""
    data = path.read_bytes()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for counter in range(100):
        suffix = f".ssh-manager-backup-{stamp}" + (f"-{counter}" if counter else "")
        candidate = path.with_name(path.name + suffix)
        try:
            with open(candidate, "xb") as handle:
                handle.write(data)
            return candidate
        except FileExistsError:
            continue
    raise ConfigError(f"Nije moguće napraviti jedinstvenu rezervnu kopiju fajla {path}.")


@dataclass
class ConfigUpdateResult:
    path: Path
    backup: Path | None
    created: bool
    validated: bool
    warnings: list[str] = field(default_factory=list)


class SSHConfigManager:
    def __init__(
        self,
        config_path: Path,
        runner: CommandRunner,
        ssh: str | None,
        home: Path,
        *,
        is_default_path: bool = True,
    ) -> None:
        self.path = config_path
        self.runner = runner
        self.ssh = ssh
        self.home = home
        self.is_default_path = is_default_path

    def load(self) -> SSHConfigDocument:
        if not self.path.exists():
            return SSHConfigDocument("")
        if not self.path.is_file():
            raise ConfigError(f"{self.path} postoji, ali nije običan fajl.")
        try:
            data = self.path.read_bytes()
        except OSError as exc:
            raise ConfigError(f"Nije moguće pročitati {self.path}: {exc}") from exc
        return SSHConfigDocument.from_bytes(data)

    def _ssh_g(self, alias: str) -> CommandResult | None:
        if not self.ssh:
            return None
        args = [self.ssh, "-G"]
        if not self.is_default_path:
            args += ["-F", str(self.path)]
        args.append(alias)
        try:
            return self.runner.run(args, timeout=20)
        except CommandError:
            return None

    def resolve(self, alias: str) -> dict[str, list[str]] | None:
        """Return the effective options for ``alias`` (via ``ssh -G``), or None."""
        result = self._ssh_g(alias)
        if result is None or not result.ok:
            return None
        return parse_ssh_g_output(result.stdout)

    def check_syntax(self, alias: str) -> tuple[bool | None, str]:
        """True/False if ``ssh -G`` accepts the config, None if it cannot be checked."""
        result = self._ssh_g(alias)
        if result is None:
            return None, "ssh -G nije dostupan."
        return result.ok, excerpt(result.stderr)

    def apply(
        self, spec: HostSpec, *, replace: bool = False, rollback_on_invalid: bool = True
    ) -> ConfigUpdateResult:
        existed = self.path.exists()
        document = self.load()
        original = document.to_bytes()
        created = datetime.now().strftime("%Y-%m-%d")
        if replace:
            updated = document.with_block_replaced(spec, created)
        else:
            updated = document.with_block_added(spec, created)

        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            backup = create_backup(self.path) if existed else None
            atomic_write_bytes(self.path, updated.to_bytes())
        except OSError as exc:
            raise ConfigError(
                f"Nije moguće upisati {self.path}: {exc}. Originalni config nije promenjen."
            ) from exc

        result = ConfigUpdateResult(self.path, backup, created=not existed, validated=False)
        check = self._ssh_g(spec.alias)
        if check is None:
            result.warnings.append("Config nije moguće proveriti komandom 'ssh -G'.")
            return result
        if not check.ok:
            detail = excerpt(check.stderr) or f"izlazni kod {check.returncode}"
            if rollback_on_invalid:
                try:
                    atomic_write_bytes(self.path, original)
                except OSError as exc:
                    raise ConfigError(
                        f"'ssh -G' je odbio izmenjeni config ({detail}), a vraćanje originala "
                        f"nije uspelo: {exc}. Vratite ga iz rezervne kopije {backup}."
                    ) from exc
                raise ConfigError(
                    f"'ssh -G' je odbio izmenjeni config, pa je originalni sadržaj vraćen: {detail}"
                )
            result.warnings.append(f"'ssh -G' je prijavio greške: {detail}")
            return result
        result.validated = True
        result.warnings.extend(compare_resolved(spec, parse_ssh_g_output(check.stdout), self.home))
        return result


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #

PUBLIC_KEY_RE = re.compile(
    r"^(?P<type>ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|"
    r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) "
    r"(?P<body>[A-Za-z0-9+/]+={0,3})(?: (?P<comment>.*))?$"
)
MAX_PUBLIC_KEY_BYTES = 16 * 1024


class KeyType(StrEnum):
    ED25519 = "ed25519"
    RSA = "rsa"


@dataclass(frozen=True)
class KeyPaths:
    private: Path
    public: Path


def read_public_key(path: Path) -> str:
    """Read and validate a *public* key file. Refuses anything else."""
    if path.suffix != ".pub":
        raise ValidationError(f"{path} nije .pub fajl, pa neće biti pročitan.")
    if not path.is_file():
        raise SSHManagerError(f"Fajl javnog ključa nije pronađen: {path}")
    if path.stat().st_size > MAX_PUBLIC_KEY_BYTES:
        raise ValidationError(f"{path} je prevelik da bi bio javni ključ.")
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if "PRIVATE KEY" in text or "\n" in text or not PUBLIC_KEY_RE.fullmatch(text):
        raise ValidationError(f"{path} ne sadrži tačno jedan OpenSSH javni ključ.")
    return text


def _safe_hostname() -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "", socket.gethostname()) or "computer"


def current_windows_principal() -> str | None:
    user = os.environ.get("USERNAME")
    if not user:
        return None
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{user}" if domain else user


class KeyManager:
    def __init__(
        self, ssh_dir: Path, runner: CommandRunner, ssh_keygen: str | None, icacls: str | None = None
    ) -> None:
        self.ssh_dir = ssh_dir
        self.runner = runner
        self.ssh_keygen = ssh_keygen
        self.icacls = icacls

    def paths(self, name: str) -> KeyPaths:
        name = validate_key_name(name)
        private = self.ssh_dir / name
        # Defence in depth against path traversal.
        if private.parent.resolve() != self.ssh_dir.resolve():
            raise ValidationError("Ključ mora biti sačuvan direktno u .ssh direktorijumu.")
        return KeyPaths(private, private.with_name(name + ".pub"))

    def existing_files(self, name: str) -> list[Path]:
        paths = self.paths(name)
        return [p for p in (paths.private, paths.public) if p.exists() or p.is_symlink()]

    def ensure_ssh_dir(self) -> None:
        if self.ssh_dir.exists() and not self.ssh_dir.is_dir():
            raise SSHManagerError(f"{self.ssh_dir} postoji, ali nije direktorijum.")
        self.ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    def generate(
        self, name: str, key_type: KeyType, use_passphrase: bool, comment: str | None = None
    ) -> KeyPaths:
        if not self.ssh_keygen:
            raise CommandError("ssh-keygen nije pronađen.\n" + OPENSSH_INSTALL_HINT)
        paths = self.paths(name)
        existing = self.existing_files(name)
        if existing:
            raise KeyExistsError(
                "Postojeći fajlovi neće biti prepisani: " + ", ".join(map(str, existing))
            )
        self.ensure_ssh_dir()
        args = [self.ssh_keygen, "-t", str(key_type)]
        if key_type is KeyType.RSA:
            args += ["-b", "4096"]
        args += ["-a", "100", "-f", str(paths.private), "-C", comment or f"{name}@{_safe_hostname()}"]
        if use_passphrase:
            # ssh-keygen prompts on the console; the passphrase never passes through this program.
            result = self.runner.run(args, interactive=True)
        else:
            result = self.runner.run([*args, "-N", ""], timeout=120)
        if not result.ok:
            detail = excerpt(result.output)
            raise CommandError(
                f"ssh-keygen nije uspeo (izlazni kod {result.returncode})."
                + (f"\n{detail}" if detail else "")
            )
        missing = [p for p in (paths.private, paths.public) if not p.is_file()]
        if missing:
            raise CommandError(
                "ssh-keygen je završio, ali ovi fajlovi nedostaju: " + ", ".join(map(str, missing))
            )
        return paths

    def restrict_permissions(self, private_key: Path) -> tuple[bool, str]:
        """Limit access to the new private key to the current user where supported."""
        if os.name != "nt":
            try:
                os.chmod(private_key, 0o600)
            except OSError as exc:
                return False, f"chmod nije uspeo: {exc}"
            return True, "dozvole postavljene na 600 (čitanje i pisanje samo za vlasnika)"
        principal = current_windows_principal()
        if not self.icacls or not principal:
            return False, (
                "icacls ili ime trenutnog korisnika nisu dostupni; "
                "dozvole su ostale kako ih je postavio ssh-keygen"
            )
        result = self.runner.run(
            [self.icacls, str(private_key), "/inheritance:r", "/grant:r", f"{principal}:F"]
        )
        if not result.ok:
            return False, (
                f"icacls nije uspeo (izlazni kod {result.returncode}); "
                "dozvole su ostale kako ih je postavio ssh-keygen"
            )
        return True, f"nasleđene dozvole uklonjene; puna kontrola dodeljena korisniku {principal}"

    def fingerprint(self, public_key: Path) -> str | None:
        if not self.ssh_keygen:
            return None
        try:
            result = self.runner.run([self.ssh_keygen, "-l", "-f", str(public_key)])
        except CommandError:
            return None
        return result.stdout.strip() or None if result.ok else None


# --------------------------------------------------------------------------- #
# ssh-agent
# --------------------------------------------------------------------------- #


class AgentState(StrEnum):
    RUNNING = "pokrenut"
    NOT_RUNNING = "nije pokrenut"
    UNKNOWN = "nepoznato"


def agent_state(runner: CommandRunner, ssh_add: str | None) -> AgentState:
    """Use `ssh-add -l` exit codes: 0/1 = agent reachable, 2 = no agent."""
    if not ssh_add:
        return AgentState.UNKNOWN
    try:
        result = runner.run([ssh_add, "-l"], timeout=15)
    except CommandError:
        return AgentState.UNKNOWN
    if result.returncode in (0, 1):
        return AgentState.RUNNING
    if result.returncode == 2:
        return AgentState.NOT_RUNNING
    return AgentState.UNKNOWN


# --------------------------------------------------------------------------- #
# GitHub CLI integration
# --------------------------------------------------------------------------- #


@dataclass
class GhAuthStatus:
    logged_in: bool
    account: str | None = None
    scopes: frozenset[str] | None = None  # None means "could not be determined"
    token_source: str | None = None
    token_kind: str | None = None
    problem: str | None = None

    @property
    def uses_env_token(self) -> bool:
        return self.token_source in ENV_TOKEN_SOURCES

    def has_key_scope(self) -> bool | None:
        if self.scopes is None:
            return None
        return bool(self.scopes & GITHUB_KEY_SCOPES)


_GH_ACCOUNT_RE = re.compile(
    r"(?P<state>Logged in to|Failed to log in to) github\.com (?:account|as) "
    r"(?P<account>[A-Za-z0-9-]+)(?: \((?P<source>[^)]*)\))?"
)
_GH_SCOPES_RE = re.compile(r"Token scopes:\s*(?P<scopes>.*)$")
_GH_TOKEN_RE = re.compile(r"Token:\s*(?P<prefix>[A-Za-z_]+?_)\*")


def parse_gh_auth_status(output: str) -> GhAuthStatus:
    """Parse `gh auth status` output (both the older and newer formats)."""
    sections: list[tuple[re.Match[str], list[str]]] = []
    for line in output.splitlines():
        match = _GH_ACCOUNT_RE.search(line)
        if match:
            sections.append((match, []))
        elif sections:
            sections[-1][1].append(line)
    if not sections:
        problem = "niste prijavljeni na github.com" if "not logged" in output.lower() else None
        return GhAuthStatus(logged_in=False, problem=problem or excerpt(output, 3) or None)

    chosen = sections[0]
    for section in sections:
        if any(re.search(r"Active account:\s*true", line) for line in section[1]):
            chosen = section
            break
    match, details = chosen
    scopes: frozenset[str] | None = None
    token_kind = None
    for line in details:
        scope_match = _GH_SCOPES_RE.search(line)
        if scope_match:
            raw = scope_match["scopes"].strip()
            if raw.lower() in ("", "none"):
                scopes = frozenset()
            else:
                scopes = frozenset(
                    item.strip().strip("'\"") for item in raw.split(",") if item.strip()
                )
        token_match = _GH_TOKEN_RE.search(line)
        if token_match:
            token_kind = token_match["prefix"]
    if token_kind == "github_pat_" and not scopes:
        scopes = None  # fine-grained tokens have permissions, not OAuth scopes
    logged_in = match["state"] == "Logged in to"
    problem = None
    if not logged_in:
        problem = excerpt("\n".join(details), 3) or "autentifikacija nije uspela"
    return GhAuthStatus(
        logged_in=logged_in,
        account=match["account"],
        scopes=scopes,
        token_source=match["source"],
        token_kind=token_kind,
        problem=problem,
    )


class GhErrorKind(StrEnum):
    DUPLICATE = "duplicate"
    PERMISSION = "permission"
    AUTH = "auth"
    POLICY = "policy"
    NETWORK = "network"
    UNKNOWN = "unknown"


# Matched against gh's (English) output.
_GH_ERROR_RULES: tuple[tuple[GhErrorKind, tuple[str, ...]], ...] = (
    (GhErrorKind.DUPLICATE, ("key is already in use", "already exists", "already been taken")),
    (GhErrorKind.POLICY, ("saml", "single sign-on", "ip allow list", "organization policy", "enterprise policy", "has been disabled by")),
    (GhErrorKind.AUTH, ("http 401", "bad credentials", "authentication required", "not logged in", "token is invalid", "token has expired", "gh auth login")),
    (GhErrorKind.PERMISSION, ("admin:public_key", "write:public_key", "http 403", "http 404", "resource not accessible", "insufficient", "scope")),
    (GhErrorKind.NETWORK, ("could not resolve", "no such host", "dial tcp", "connection refused", "connection reset", "timeout", "timed out", "tls handshake", "network is unreachable", "proxyconnect")),
)

GH_ERROR_EXPLANATIONS: dict[GhErrorKind, str] = {
    GhErrorKind.DUPLICATE: (
        "GitHub već ima ovaj javni ključ, na drugom nalogu ili kao deploy key. "
        "Isti ključ može biti registrovan na GitHub-u samo jednom; napravite novi ključ za ovaj nalog."
    ),
    GhErrorKind.PERMISSION: (
        "GitHub CLI token nema dozvolu da upravlja SSH ključevima. Potreban OAuth scope: "
        f"{GITHUB_REFRESH_SCOPE} (ili admin:public_key). Pokrenite: {GH_REFRESH_COMMAND}"
    ),
    GhErrorKind.AUTH: f"GitHub CLI prijava nedostaje ili je istekla. Pokrenite: {GH_LOGIN_COMMAND}",
    GhErrorKind.POLICY: (
        "Pravila organizacije ili preduzeća (na primer SAML jednokratna prijava ili lista "
        "dozvoljenih IP adresa) blokirala su zahtev. Autorizujte token za organizaciju ili se "
        "obratite administratoru."
    ),
    GhErrorKind.NETWORK: (
        "Došlo je do mrežnog problema pri povezivanju sa GitHub-om. Proverite internet vezu, "
        "proxy i firewall, pa pokušajte ponovo."
    ),
    GhErrorKind.UNKNOWN: "GitHub CLI je prijavio neočekivanu grešku.",
}


def classify_gh_error(text: str) -> GhErrorKind:
    lower = text.lower()
    for kind, needles in _GH_ERROR_RULES:
        if any(needle in lower for needle in needles):
            return kind
    return GhErrorKind.UNKNOWN


@dataclass
class GhAddResult:
    success: bool
    already_present: bool = False
    error_kind: GhErrorKind | None = None
    message: str = ""


class VerifyStatus(StrEnum):
    VERIFIED = "verified"
    SIGNING_ONLY = "signing-only"
    TITLE_ONLY = "title-only"
    NOT_FOUND = "not-found"
    ERROR = "error"


def find_key_in_listing(listing: str, public_key: str, title: str) -> VerifyStatus:
    """Check `gh ssh-key list` output for our key as an *authentication* key."""
    match = PUBLIC_KEY_RE.fullmatch(public_key.strip())
    if not match:
        return VerifyStatus.ERROR
    body = match["body"]
    rows = [line for line in listing.splitlines() if body in line]
    if rows:
        if any("authentication" in row.lower() for row in rows):
            return VerifyStatus.VERIFIED
        if all("signing" in row.lower() for row in rows):
            return VerifyStatus.SIGNING_ONLY
        return VerifyStatus.VERIFIED  # older gh versions do not print a type column
    for line in listing.splitlines():
        if line.split("\t")[0].strip() == title:
            return VerifyStatus.TITLE_ONLY
    return VerifyStatus.NOT_FOUND


class GitHubCLI:
    _ENV = {"NO_COLOR": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_PROMPT_DISABLED": "1"}

    def __init__(self, runner: CommandRunner, gh: str | None) -> None:
        self.runner = runner
        self.gh = gh

    @property
    def available(self) -> bool:
        return self.gh is not None

    def _require(self) -> str:
        if not self.gh:
            raise CommandError("GitHub CLI (gh) nije pronađen.\n" + GH_INSTALL_HINT)
        return self.gh

    def _run(self, *args: str, timeout: float = COMMAND_TIMEOUT_SECONDS) -> CommandResult:
        return self.runner.run([self._require(), *args], timeout=timeout, env_overrides=self._ENV)

    def version(self) -> str | None:
        try:
            result = self._run("--version", timeout=15)
        except CommandError:
            return None
        return result.stdout.splitlines()[0].strip() if result.ok and result.stdout else None

    def auth_status(self) -> GhAuthStatus:
        # The exit code is non-zero if *any* account has a problem, so the
        # parsed state of the active account is authoritative.
        result = self._run("auth", "status", "--hostname", GITHUB_HOST)
        return parse_gh_auth_status(result.output)

    def login(self) -> int:
        return self.runner.run(
            [self._require(), "auth", "login", "--hostname", GITHUB_HOST, "--git-protocol", "ssh",
             "--web", "--skip-ssh-key"],
            interactive=True,
        ).returncode

    def refresh_scopes(self) -> int:
        return self.runner.run(
            [self._require(), "auth", "refresh", "--hostname", GITHUB_HOST, "--scopes",
             GITHUB_REFRESH_SCOPE],
            interactive=True,
        ).returncode

    def add_key(self, public_key: Path, title: str) -> GhAddResult:
        read_public_key(public_key)  # refuses anything that is not a public key
        title = validate_key_name(title)
        try:
            result = self._run(
                "ssh-key", "add", str(public_key), "--type", "authentication", "--title", title,
                timeout=90,
            )
        except CommandError as exc:
            return GhAddResult(False, error_kind=classify_gh_error(str(exc)), message=str(exc))
        if result.ok:
            return GhAddResult(True, already_present="already exists" in result.output.lower())
        return GhAddResult(
            False, error_kind=classify_gh_error(result.output), message=excerpt(result.output, 4)
        )

    def verify_key(self, public_key: str, title: str) -> tuple[VerifyStatus, str]:
        try:
            result = self._run("ssh-key", "list")
        except CommandError as exc:
            return VerifyStatus.ERROR, str(exc)
        if not result.ok:
            kind = classify_gh_error(result.output)
            return VerifyStatus.ERROR, GH_ERROR_EXPLANATIONS[kind]
        return find_key_in_listing(result.stdout, public_key, title), ""


# --------------------------------------------------------------------------- #
# Connection tests
# --------------------------------------------------------------------------- #

_GITHUB_SUCCESS_RE = re.compile(r"Hi (?P<who>[^\s!]+)! You've successfully authenticated")
_SERVER_AUTH_RE = re.compile(r"Authenticated to \S+|Authentication succeeded")

# The first element is matched against ssh's (English) output.
_SSH_FAILURE_HINTS: tuple[tuple[str, str], ...] = (
    ("REMOTE HOST IDENTIFICATION HAS CHANGED",
     "Host ključ servera je promenjen. To može značiti napad tipa man-in-the-middle ili ponovo "
     "instaliran server. Proverite novi otisak (fingerprint) sa vlasnikom servera pre izmene "
     "known_hosts fajla."),
    ("Host key verification failed",
     "Host ključ nije prihvaćen. Povežite se ponovo i potvrdite otisak tek pošto ga uporedite sa "
     "pouzdanim izvorom. Nikada ne isključujte proveru host ključa."),
    ("Permission denied",
     "Server je odbio ključ. Za GitHub proverite da li je javni ključ registrovan na vašem nalogu "
     "(gh ssh-key list). Za server proverite ~/.ssh/authorized_keys ciljnog korisnika."),
    ("Could not resolve hostname", "Ime hosta nije moguće razrešiti. Proverite HostName i DNS/mrežu."),
    ("timed out", "Isteklo je vreme za povezivanje. Proverite mrežu, firewall i port."),
    ("Connection refused", "Veza je odbijena. Proverite da li SSH servis radi i da li je port ispravan."),
    ("UNPROTECTED PRIVATE KEY FILE", "Dozvole privatnog ključa su previše otvorene. Ograničite pristup samo na svog korisnika."),
    ("Bad owner or permissions", "SSH config ili ključ imaju nebezbedne dozvole. Pristup smeju imati samo vaš korisnik (i SYSTEM/Administrators)."),
    ("no such identity", "IdentityFile ne postoji. Proverite upravljani blok u SSH config fajlu."),
    ("Too many authentication failures", "Ponuđeno je previše ključeva. Proverite da je za alias postavljeno 'IdentitiesOnly yes'."),
    ("Bad configuration option", "SSH config sadrži neispravnu opciju."),
)


@dataclass
class ConnectionResult:
    success: bool
    summary: str
    hints: list[str] = field(default_factory=list)
    github_identity: str | None = None
    deploy_key: bool = False


def ssh_failure_hints(output: str) -> list[str]:
    hints = [hint for needle, hint in _SSH_FAILURE_HINTS if needle.lower() in output.lower()]
    return hints or ["Pokrenite 'ssh -v' sa istim aliasom za detaljnu dijagnostiku."]


def interpret_github_ssh(output: str, returncode: int | None) -> ConnectionResult:
    """GitHub returns exit code 1 even on success, so only the greeting counts."""
    match = _GITHUB_SUCCESS_RE.search(output)
    if match:
        who = match["who"]
        if "/" in who:
            return ConnectionResult(
                True,
                f"Autentifikacija je uspela pomoću DEPLOY ključa za repozitorijum '{who}'.",
                hints=["Ovaj ključ je deploy key repozitorijuma, a ne ključ za autentifikaciju "
                       "naloga. Daje pristup samo tom jednom repozitorijumu."],
                github_identity=who,
                deploy_key=True,
            )
        return ConnectionResult(
            True, f"GitHub je potvrdio ovaj ključ za korisnika '{who}'.", github_identity=who
        )
    return ConnectionResult(
        False,
        f"GitHub autentifikacija NIJE potvrđena (izlazni kod ssh: {returncode}).",
        hints=ssh_failure_hints(output),
    )


def interpret_server_ssh(result: StreamResult) -> ConnectionResult:
    if result.stopped_early or _SERVER_AUTH_RE.search(result.output):
        return ConnectionResult(True, "Autentifikacija je uspela. Veza je odmah zatvorena.")
    if result.timed_out:
        return ConnectionResult(
            False,
            f"Nema rezultata u roku od {INTERACTIVE_TEST_TIMEOUT_SECONDS} sekundi; test je prekinut.",
            hints=ssh_failure_hints(result.output),
        )
    return ConnectionResult(
        False,
        f"Autentifikacija NIJE potvrđena (izlazni kod ssh: {result.returncode}).",
        hints=ssh_failure_hints(result.output),
    )


def known_host_present(runner: CommandRunner, ssh_keygen: str | None, host: str) -> bool | None:
    if not ssh_keygen:
        return None
    try:
        result = runner.run([ssh_keygen, "-F", host], timeout=15)
    except CommandError:
        return None
    if result.returncode == 0 and result.stdout.strip():
        return True
    return False if result.returncode in (0, 1) else None


# --------------------------------------------------------------------------- #
# Console UI helpers
# --------------------------------------------------------------------------- #


class Console:
    def __init__(self, input_func: Callable[[str], str] = input, out: TextIO | None = None) -> None:
        self._input = input_func
        self._out = out

    @property
    def out(self) -> TextIO:
        return self._out or sys.stdout

    def print(self, text: str = "") -> None:
        self.out.write(f"{text}\n")
        self.out.flush()

    def labeled(self, prefix: str, text: str) -> None:
        indent = " " * len(prefix)
        for number, line in enumerate(str(text).splitlines() or [""]):
            self.print(f"{prefix if number == 0 else indent}{line}")

    def heading(self, title: str) -> None:
        self.print()
        self.print(title)
        self.print("-" * len(title))

    def info(self, text: str) -> None:
        self.labeled("  ", text)

    def ok(self, text: str) -> None:
        self.labeled("[OK] ", text)

    def warn(self, text: str) -> None:
        self.labeled("[UPOZORENJE] ", text)

    def error(self, text: str) -> None:
        self.labeled("[GREŠKA] ", text)

    def ask(self, prompt: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default else ""
        try:
            raw = self._input(f"{prompt}{suffix}: ")
        except EOFError as exc:
            raise UserAbort() from exc
        return raw.strip() or (default or "")

    def ask_validated(self, prompt: str, validator: Callable[[str], T]) -> T:
        while True:
            try:
                return validator(self.ask(prompt))
            except ValidationError as exc:
                self.error(str(exc))

    def confirm(self, prompt: str, default: bool) -> bool:
        hint = "D/n" if default else "d/N"
        while True:
            answer = self.ask(f"{prompt} [{hint}]").lower()
            if not answer:
                return default
            if answer in YES_ANSWERS:
                return True
            if answer in NO_ANSWERS:
                return False
            self.error("Odgovorite sa 'd' (da) ili 'n' (ne).")

    def choose(self, prompt: str, options: Sequence[tuple[str, str]]) -> str:
        for number, (_, label) in enumerate(options, 1):
            self.print(f"  {number}. {label}")
        while True:
            raw = self.ask(prompt)
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return options[int(raw) - 1][0]
            self.error(f"Unesite broj od 1 do {len(options)}.")


class StepStatus(StrEnum):
    OK = "OK"
    WARNING = "UPOZORENJE"
    FAILED = "NEUSPEH"
    SKIPPED = "PRESKOČENO"


@dataclass
class Step:
    name: str
    status: StepStatus
    detail: str = ""


class StepReport:
    """Records what succeeded and what failed so partial results are always reported."""

    def __init__(self) -> None:
        self.steps: list[Step] = []

    def add(self, name: str, status: StepStatus, detail: str = "") -> None:
        self.steps.append(Step(name, status, detail))

    @property
    def failed(self) -> bool:
        return any(step.status is StepStatus.FAILED for step in self.steps)

    def status_of(self, name: str) -> StepStatus | None:
        for step in reversed(self.steps):
            if step.name == name:
                return step.status
        return None

    def render(self, console: Console) -> None:
        if not self.steps:
            return
        console.heading("Rezime")
        for step in self.steps:
            label = f"[{step.status}]".ljust(13)
            console.labeled(f"  {label} ", f"{step.name}" + (f": {step.detail}" if step.detail else ""))


# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Environment:
    home: Path
    ssh_dir: Path
    config_path: Path

    @classmethod
    def default(cls) -> Environment:
        home = Path.home()
        ssh_dir = home / ".ssh"
        return cls(home, ssh_dir, ssh_dir / "config")

    @property
    def is_default_config(self) -> bool:
        return self.config_path == Path.home() / ".ssh" / "config"


@dataclass(frozen=True)
class NameDecision:
    name: str
    reuse_key: bool = False
    config_action: str = "add"  # "add", "replace" or "keep"


STEP_KEY = "Generisanje SSH ključa"
STEP_PERMISSIONS = "Ograničavanje dozvola privatnog ključa"
STEP_CONFIG = "Ažuriranje SSH config fajla"
STEP_VALIDATE = "Provera SSH config fajla (ssh -G)"
STEP_GH_ADD = "Registracija ključa na GitHub-u"
STEP_GH_VERIFY = "Provera ključa komandom 'gh ssh-key list'"
STEP_AGENT = "ssh-agent"


class App:
    def __init__(self, console: Console, runner: CommandRunner, tools: Tools, env: Environment) -> None:
        self.console = console
        self.runner = runner
        self.tools = tools
        self.env = env
        self.keys = KeyManager(env.ssh_dir, runner, tools.ssh_keygen, tools.icacls)
        self.config = SSHConfigManager(
            env.config_path, runner, tools.ssh, env.home, is_default_path=env.is_default_config
        )
        self.gh = GitHubCLI(runner, tools.gh)

    # ----- menu -------------------------------------------------------------

    def run(self) -> int:
        c = self.console
        c.print(f"SSH Key Manager {__version__}")
        c.info(f"Direktorijum ključeva: {self.env.ssh_dir}")
        c.info(f"SSH config:            {self.env.config_path}")
        self._warn_missing_openssh()
        actions: dict[str, Callable[[], None]] = {
            "1": self.create_github_key,
            "2": self.create_server_key,
            "3": self.list_managed,
            "4": self.test_connection,
        }
        while True:
            c.print()
            c.print("Glavni meni")
            c.print("  1. Kreiraj SSH ključ za GitHub")
            c.print("  2. Kreiraj SSH ključ za udaljeni server")
            c.print("  3. Prikaži upravljane SSH ključeve i konfiguracije")
            c.print("  4. Testiraj SSH vezu")
            c.print("  5. Izlaz")
            try:
                choice = c.ask("Izaberite opciju [1-5]")
            except UserAbort:
                c.print()
                return 0
            if choice == "5":
                c.print("Doviđenja.")
                return 0
            action = actions.get(choice)
            if action is None:
                c.error("Neispravan izbor. Unesite broj od 1 do 5.")
                continue
            try:
                action()
            except UserAbort:
                c.print()
                c.warn("Otkazano. Povratak u glavni meni.")
            except KeyboardInterrupt:
                c.print()
                c.warn("Prekinuto. Povratak u glavni meni.")
            except SSHManagerError as exc:
                c.error(str(exc))

    def _warn_missing_openssh(self) -> bool:
        missing = [name for name, path in (("ssh", self.tools.ssh), ("ssh-keygen", self.tools.ssh_keygen)) if not path]
        if missing:
            self.console.warn(f"Nedostaje obavezan program: {', '.join(missing)}.\n{OPENSSH_INSTALL_HINT}")
            return False
        return True

    # ----- shared prompts ---------------------------------------------------

    def _ask_name(self, kind: HostKind, document: SSHConfigDocument) -> NameDecision:
        c = self.console
        example = "github-work" if kind is HostKind.GITHUB else "production-server"
        while True:
            raw = c.ask(f"Naziv ključa (koristi se i kao SSH host alias), npr. {example}")
            try:
                name = validate_key_name(raw)
                if kind is HostKind.GITHUB:
                    suggestion = suggest_github_name(name)
                    if suggestion != name and c.confirm(
                        f"Da li da koristim '{suggestion}', da bi alias jasno označavao GitHub?",
                        default=True,
                    ):
                        name = validate_key_name(suggestion)
            except ValidationError as exc:
                c.error(str(exc))
                continue
            decision = self._resolve_name_conflicts(name, kind, document)
            if decision is not None:
                return decision

    def _resolve_name_conflicts(
        self, name: str, kind: HostKind, document: SSHConfigDocument
    ) -> NameDecision | None:
        c = self.console
        conflicts = document.find_alias_conflicts(name)
        if conflicts.unmanaged_lines:
            lines = ", ".join(map(str, conflicts.unmanaged_lines))
            c.error(
                f"Host alias '{name}' je već definisan u {self.env.config_path} (red {lines}) "
                "unosom kojim ovaj alat ne upravlja. Taj unos neće biti promenjen. "
                "Izaberite drugi naziv."
            )
            return None
        if conflicts.wildcard_patterns:
            c.warn(
                f"Postojeći Host obrasci sa džokerima takođe odgovaraju aliasu '{name}': "
                f"{', '.join(conflicts.wildcard_patterns)}. Njihove opcije i dalje važe tamo gde "
                "ih novi blok ne postavlja."
            )
            if not c.confirm("Nastaviti sa ovim nazivom?", default=True):
                return None

        paths = self.keys.paths(name)
        has_private, has_public = paths.private.exists(), paths.public.exists()
        reuse = False
        if has_private or has_public:
            if not (has_private and has_public):
                present = paths.private if has_private else paths.public
                c.error(
                    f"{present} već postoji, ali odgovarajući fajl ključa nedostaje. "
                    "Postojeći fajlovi se nikada ne prepisuju. Izaberite drugi naziv."
                )
                return None
            c.warn(f"Ključ pod nazivom '{name}' već postoji:\n{paths.private}\n{paths.public}")
            choice = c.choose(
                "Šta želite da uradite?",
                [
                    ("other", "Izaberi drugi naziv (preporučeno)"),
                    ("reuse", "Koristi postojeći ključ takav kakav jeste (fajlovi ključa se ne menjaju)"),
                ],
            )
            if choice == "other":
                return None
            reuse = True

        block = conflicts.managed
        if block is None:
            if not self._alias_is_unused(name):
                return None
            return NameDecision(name, reuse, "add")
        if block.kind != kind:
            c.error(f"'{name}' je već upravljani unos tipa '{block.kind}'. Izaberite drugi naziv.")
            return None
        c.warn(
            f"Upravljani blok u SSH config fajlu za '{name}' već postoji "
            f"(HostName {block.options.get('hostname', '?')}, User {block.options.get('user', '?')})."
        )
        choice = c.choose(
            "Šta želite da uradite?",
            [
                ("other", "Izaberi drugi naziv"),
                ("keep", "Zadrži postojeći upravljani blok bez izmena"),
                ("replace", "Zameni postojeći upravljani blok (pre toga se pravi rezervna kopija config fajla)"),
            ],
        )
        if choice == "other":
            return None
        if choice == "replace" and not c.confirm(
            f"Zameniti samo redove između BEGIN/END oznaka za '{name}'?", default=False
        ):
            return None
        return NameDecision(name, reuse, choice)

    def _alias_is_unused(self, name: str) -> bool:
        """Catch aliases defined in Include files or by HostName patterns."""
        options = self.config.resolve(name)
        if not options:
            return True
        hostname = (options.get("hostname") or [name])[0]
        if hostname.casefold() == name.casefold():
            return True
        self.console.warn(
            f"SSH već razrešava '{name}' u '{hostname}' kroz postojeću konfiguraciju "
            "(moguće preko Include fajla ili pravila sa džokerom)."
        )
        return self.console.confirm("Ipak koristiti ovaj naziv?", default=False)

    def _ask_passphrase(self) -> bool:
        self.console.info(
            "Passphrase (lozinka ključa) šifruje privatni ključ na disku. ssh-keygen je traži\n"
            "direktno; ovaj alat je nikada ne vidi, ne čuva i ne beleži."
        )
        return self.console.confirm("Zaštititi privatni ključ passphrase-om?", default=True)

    def _print_plan(self, rows: Sequence[tuple[str, str]]) -> None:
        self.console.heading("Plan")
        width = max(len(label) for label, _ in rows)
        for label, value in rows:
            self.console.labeled(f"  {label.ljust(width)} : ", value)

    @staticmethod
    def _passphrase_label(decision: NameDecision, use_passphrase: bool) -> str:
        if decision.reuse_key:
            return "nije primenljivo (postojeći ključ)"
        return "da (ssh-keygen će je tražiti)" if use_passphrase else "ne"

    # ----- shared execution -------------------------------------------------

    def _prepare_key_and_config(
        self,
        decision: NameDecision,
        spec: HostSpec | None,
        key_type: KeyType,
        use_passphrase: bool,
        report: StepReport,
    ) -> KeyPaths | None:
        paths = self.keys.paths(decision.name)
        if decision.reuse_key:
            report.add(STEP_KEY, StepStatus.SKIPPED, "koristi se postojeći ključ; njegovi fajlovi nisu menjani")
        else:
            try:
                paths = self.keys.generate(decision.name, key_type, use_passphrase)
            except SSHManagerError as exc:
                report.add(STEP_KEY, StepStatus.FAILED, str(exc))
                return None
            fingerprint = self.keys.fingerprint(paths.public)
            report.add(STEP_KEY, StepStatus.OK, f"{paths.private}" + (f" ({fingerprint})" if fingerprint else ""))
            ok, message = self.keys.restrict_permissions(paths.private)
            report.add(STEP_PERMISSIONS, StepStatus.OK if ok else StepStatus.WARNING, message)

        if spec is None or decision.config_action == "keep":
            report.add(STEP_CONFIG, StepStatus.SKIPPED, "postojeći upravljani blok je zadržan bez izmena")
            return paths

        syntax_ok, syntax_detail = self.config.check_syntax(decision.name)
        if syntax_ok is False:
            self.console.warn(f"Vaš postojeći SSH config već prijavljuje greške:\n{syntax_detail}")
            if not self.console.confirm(
                "Ipak dodati upravljani blok (ne može se potpuno proveriti)?", default=False
            ):
                report.add(STEP_CONFIG, StepStatus.SKIPPED, "postojeći config ima greške; nije menjan")
                return paths
        try:
            result = self.config.apply(
                spec, replace=decision.config_action == "replace", rollback_on_invalid=syntax_ok is not False
            )
        except ConfigError as exc:
            report.add(STEP_CONFIG, StepStatus.FAILED, str(exc))
            return paths
        verb = "zamenjen" if decision.config_action == "replace" else "dodat"
        detail = f"upravljani blok '{spec.alias}' {verb} u {result.path}"
        if result.created:
            detail += " (novi fajl)"
        if result.backup:
            detail += f"; rezervna kopija: {result.backup.name}"
        report.add(STEP_CONFIG, StepStatus.OK, detail)
        if result.validated and not result.warnings:
            report.add(STEP_VALIDATE, StepStatus.OK, f"'{spec.alias}' se razrešava u {spec.user}@{spec.hostname}")
        elif result.warnings:
            report.add(STEP_VALIDATE, StepStatus.WARNING, " ".join(result.warnings))
        return paths

    def _agent_step(self, paths: KeyPaths, used_passphrase: bool, report: StepReport) -> None:
        state = agent_state(self.runner, self.tools.ssh_add)
        if state is AgentState.NOT_RUNNING:
            report.add(
                STEP_AGENT,
                StepStatus.WARNING,
                "ssh-agent nije dostupan, pa 'AddKeysToAgent yes' za sada nema efekta (pogledajte napomenu ispod)",
            )
            return
        if state is AgentState.UNKNOWN:
            report.add(STEP_AGENT, StepStatus.SKIPPED, "status ssh-agent-a nije moguće utvrditi")
            return
        if used_passphrase and self.tools.ssh_add and self.console.confirm(
            "ssh-agent je pokrenut. Dodati ključ sada, da ne biste svaki put unosili passphrase?",
            default=True,
        ):
            result = self.runner.run([self.tools.ssh_add, str(paths.private)], interactive=True)
            if result.ok:
                report.add(STEP_AGENT, StepStatus.OK, "ključ je dodat u ssh-agent")
            else:
                report.add(STEP_AGENT, StepStatus.WARNING, f"ssh-add nije uspeo (izlazni kod {result.returncode})")
            return
        report.add(STEP_AGENT, StepStatus.OK, "agent je pokrenut; ključ se dodaje pri prvoj upotrebi (AddKeysToAgent yes)")

    def _offer_public_key(self, paths: KeyPaths, question: str) -> None:
        if not self.console.confirm(question, default=False):
            return
        try:
            public_key = read_public_key(paths.public)
        except SSHManagerError as exc:
            self.console.error(str(exc))
            return
        self.console.print()
        self.console.print(f"JAVNI ključ ({paths.public}) - bezbedno ga je deliti:")
        self.console.print(public_key)
        self.console.print()

    def _print_storage(self, paths: KeyPaths) -> None:
        self.console.info(f"Privatni ključ: {paths.private}  (tajna; nikada ga ne delite i ne kopirajte)")
        self.console.info(f"Javni ključ:    {paths.public}  (bezbedno ga je deliti)")

    # ----- 1. GitHub ---------------------------------------------------------

    def _prepare_github(self) -> tuple[bool, str | None] | None:
        """Return (register_automatically, account) or None if the user cancels."""
        c = self.console

        def continue_without() -> tuple[bool, str | None] | None:
            if c.confirm(
                "Nastaviti bez automatske registracije? Javni ključ možete ručno dodati na "
                f"{GITHUB_KEYS_URL}",
                default=False,
            ):
                return False, None
            return None

        if not self.gh.available:
            c.warn("GitHub CLI (gh) nije pronađen.")
            c.info(GH_INSTALL_HINT)
            return continue_without()

        c.info("Proveravam GitHub CLI prijavu (gh auth status)...")
        status = self.gh.auth_status()
        if not status.logged_in:
            c.warn("GitHub CLI nije prijavljen na github.com" + (f": {status.problem}" if status.problem else "."))
            if status.uses_env_token:
                c.info(
                    f"Token dolazi iz promenljive okruženja {status.token_source}. "
                    "Ispravite je ili uklonite, pa pokušajte ponovo."
                )
                return continue_without()
            c.info("Ovaj alat nikada ne traži tokene. Može da pokrene zvaničnu prijavu preko browsera:")
            c.info(f"  {GH_LOGIN_COMMAND}")
            if c.confirm("Pokrenuti prijavu preko browsera sada?", default=True):
                code = self.gh.login()
                if code != 0:
                    c.warn(
                        f"gh auth login je završen sa izlaznim kodom {code}. Ako opcija "
                        "'--skip-ssh-key' nije prepoznata, ažurirajte gh: winget upgrade --id GitHub.cli"
                    )
                status = self.gh.auth_status()
            if not status.logged_in:
                c.warn("I dalje niste prijavljeni.")
                return continue_without()

        c.ok(f"Prijavljeni ste na github.com kao '{status.account or 'nepoznato'}'.")
        has_scope = status.has_key_scope()
        if has_scope is False:
            current = ", ".join(sorted(status.scopes or [])) or "nema"
            c.warn(
                "GitHub CLI token još ne može da dodaje SSH ključeve. Potreban je scope "
                f"'{GITHUB_REFRESH_SCOPE}' (ili 'admin:public_key'). Trenutni scope-ovi: {current}."
            )
            if status.uses_env_token:
                c.info(
                    f"Token dolazi iz promenljive okruženja {status.token_source} "
                    "i gh ne može da ga osveži."
                )
                return continue_without()
            c.info("Traži se samo ova jedna dodatna dozvola, kroz zvanični postupak:")
            c.info(f"  {GH_REFRESH_COMMAND}")
            if c.confirm("Zatražiti ovu dozvolu sada (otvara se browser)?", default=True):
                self.gh.refresh_scopes()
                status = self.gh.auth_status()
                has_scope = status.has_key_scope() if status.logged_in else False
            if has_scope is not True:
                c.warn("Potrebna dozvola i dalje nedostaje.")
                return continue_without()
            c.ok("Token sada ima dozvolu da dodaje SSH ključeve.")
        elif has_scope is None:
            c.warn(
                "Nije moguće utvrditi dozvole tokena (na primer kod fine-grained tokena).\n"
                "Registracija će biti pokušana; potrebna je dozvola za upis 'Git SSH keys' "
                f"odnosno scope '{GITHUB_REFRESH_SCOPE}'."
            )
        else:
            c.ok("Token ima dozvolu da dodaje SSH ključeve.")
        return True, status.account

    def create_github_key(self) -> None:
        c = self.console
        c.heading("Kreiranje SSH ključa za GitHub")
        if not self._warn_missing_openssh():
            return
        prepared = self._prepare_github()
        if prepared is None:
            c.info("Ništa nije promenjeno.")
            return
        register, account = prepared
        document = self.config.load()
        decision = self._ask_name(HostKind.GITHUB, document)
        use_passphrase = False if decision.reuse_key else self._ask_passphrase()
        paths = self.keys.paths(decision.name)
        spec = HostSpec(
            alias=decision.name,
            kind=HostKind.GITHUB,
            hostname=GITHUB_HOST,
            user=GITHUB_SSH_USER,
            identity_file=identity_file_for(paths.private, self.env.home),
        )
        config_text = {
            "add": f"dodati upravljani blok 'Host {spec.alias}' u {self.env.config_path}",
            "replace": f"zameniti upravljani blok 'Host {spec.alias}' u {self.env.config_path}",
            "keep": "zadržati postojeći upravljani blok",
        }[decision.config_action]
        if register:
            github_text = (
                f"registrovati javni ključ kao ključ za AUTENTIFIKACIJU sa nazivom '{spec.alias}'"
                + (f" na nalogu '{account}'" if account else "")
            )
        else:
            github_text = "ručna registracija (nije automatska)"
        self._print_plan(
            [
                ("Privatni ključ", f"{paths.private}" + (" (postojeći, bez izmena)" if decision.reuse_key else "")),
                ("Javni ključ", str(paths.public)),
                ("Tip ključa", "postojeći ključ" if decision.reuse_key else "Ed25519"),
                ("Passphrase", self._passphrase_label(decision, use_passphrase)),
                ("SSH config", config_text),
                ("GitHub", github_text),
            ]
        )
        if not c.confirm("Nastaviti?", default=True):
            c.info("Ništa nije promenjeno.")
            return

        report = StepReport()
        try:
            key_paths = self._prepare_key_and_config(decision, spec, KeyType.ED25519, use_passphrase, report)
            if key_paths is None:
                for step in (STEP_CONFIG, STEP_GH_ADD):
                    report.add(step, StepStatus.SKIPPED, "generisanje ključa nije uspelo")
                return
            if register:
                self._register_on_github(key_paths, spec.alias, report)
            else:
                report.add(
                    STEP_GH_ADD,
                    StepStatus.SKIPPED,
                    f"dodajte {key_paths.public.name} ručno na {GITHUB_KEYS_URL} kao 'Authentication Key'",
                )
            self._agent_step(key_paths, use_passphrase, report)
        finally:
            report.render(c)

        c.heading("Gde se nalaze vaši ključevi")
        self._print_storage(key_paths)
        if report.status_of(STEP_GH_ADD) is not StepStatus.OK:
            self._offer_public_key(key_paths, "Prikazati JAVNI ključ sada, da biste ga dodali ručno?")
        self._print_github_usage(spec.alias)
        c.heading("Napomena o ssh-agent-u")
        c.info(AGENT_NOTE)
        if report.status_of(STEP_CONFIG) in (StepStatus.OK, StepStatus.SKIPPED) and c.confirm(
            f"Testirati vezu sada (ssh -T git@{spec.alias})?",
            default=report.status_of(STEP_GH_ADD) is StepStatus.OK,
        ):
            self.test_github(spec.alias)

    def _register_on_github(self, paths: KeyPaths, title: str, report: StepReport) -> None:
        try:
            public_key = read_public_key(paths.public)
        except SSHManagerError as exc:
            report.add(STEP_GH_ADD, StepStatus.FAILED, str(exc))
            return
        self.console.info("Registrujem javni ključ komandom 'gh ssh-key add --type authentication'...")
        result = self.gh.add_key(paths.public, title)
        if not result.success:
            kind = result.error_kind or GhErrorKind.UNKNOWN
            detail = f"NIJE otpremljen. {GH_ERROR_EXPLANATIONS[kind]}"
            if result.message:
                detail += f"\nIzlaz GitHub CLI-ja: {result.message}"
            report.add(STEP_GH_ADD, StepStatus.FAILED, detail)
            report.add(STEP_GH_VERIFY, StepStatus.SKIPPED, "registracija nije uspela")
            return
        report.add(
            STEP_GH_ADD,
            StepStatus.OK,
            "ključ je već bio registrovan na vašem nalogu" if result.already_present
            else f"dodat kao ključ za autentifikaciju sa nazivom '{title}'",
        )
        status, message = self.gh.verify_key(public_key, title)
        outcomes = {
            VerifyStatus.VERIFIED: (StepStatus.OK, "naveden je na vašem nalogu kao ključ za autentifikaciju"),
            VerifyStatus.SIGNING_ONLY: (
                StepStatus.WARNING,
                "naveden je samo kao ključ za POTPISIVANJE (signing); takav ključ ne može da se "
                "koristi za SSH autentifikaciju",
            ),
            VerifyStatus.TITLE_ONLY: (
                StepStatus.WARNING,
                f"ključ sa nazivom '{title}' je naveden, ali njegov sadržaj nije moguće upariti",
            ),
            VerifyStatus.NOT_FOUND: (
                StepStatus.WARNING,
                "ključ još nije pronađen u listi; proverite ponovo komandom 'gh ssh-key list'",
            ),
            VerifyStatus.ERROR: (StepStatus.WARNING, f"lista ključeva nije dostupna. {message}".strip()),
        }
        step_status, detail = outcomes[status]
        report.add(STEP_GH_VERIFY, step_status, detail)

    def _print_github_usage(self, alias: str) -> None:
        c = self.console
        c.heading("Korišćenje ključa sa Git-om")
        c.info(f"Kloniranje:               git clone {github_remote_url(alias, 'OWNER', 'REPOSITORY')}")
        c.info(f"Postojeći repozitorijum:  git remote set-url origin {github_remote_url(alias, 'OWNER', 'REPOSITORY')}")
        c.info(
            f"Koristite alias '{alias}' tačno kako je prikazan. On samo određuje koji ključ SSH koristi;\n"
            "ne daje pristup repozitorijumima kojima vaš GitHub nalog nema pristup."
        )
        self._git_ssh_tip()
        raw = c.ask(
            "Opciono: unesite OWNER/REPOSITORY da bih ispisao gotovu komandu za kloniranje "
            "(prazno za preskakanje)"
        )
        if raw:
            try:
                owner, repo = parse_owner_repo(raw)
            except ValidationError as exc:
                c.error(str(exc))
                return
            c.info(f"git clone {github_remote_url(alias, owner, repo)}")

    def _git_ssh_tip(self) -> None:
        if os.name != "nt" or not self.tools.git or not self.tools.ssh:
            return
        try:
            result = self.runner.run([self.tools.git, "config", "--global", "--get", "core.sshCommand"], timeout=15)
        except CommandError:
            return
        if result.ok and result.stdout.strip():
            return
        self.console.info(
            "Savet: Git for Windows podrazumevano koristi sopstveni ssh. On čita isti ~/.ssh/config,\n"
            "ali ne može da koristi Windows ssh-agent servis. Da bi Git koristio Windows OpenSSH (opciono):\n"
            f'  git config --global core.sshCommand "{Path(self.tools.ssh).as_posix()}"'
        )

    # ----- 2. Remote server ---------------------------------------------------

    def create_server_key(self) -> None:
        c = self.console
        c.heading("Kreiranje SSH ključa za udaljeni server")
        if not self._warn_missing_openssh():
            return
        document = self.config.load()
        decision = self._ask_name(HostKind.SERVER, document)
        spec: HostSpec | None = None
        paths = self.keys.paths(decision.name)
        if decision.config_action != "keep":
            hostname = c.ask_validated("Adresa servera (ime hosta ili IP adresa)", validate_hostname)
            if hostname.casefold() == decision.name.casefold():
                c.warn(
                    f"Alias je isti kao ime hosta, pa će svaka komanda 'ssh {hostname}' koristiti samo ovaj ključ."
                )
                if not c.confirm("Nastaviti?", default=False):
                    c.info("Ništa nije promenjeno.")
                    return
            user = c.ask_validated("Korisničko ime na serveru", validate_username)
            port = c.ask_validated("SSH port (prazno za 22)", validate_port)
            spec = HostSpec(
                alias=decision.name,
                kind=HostKind.SERVER,
                hostname=hostname,
                user=user,
                identity_file=identity_file_for(paths.private, self.env.home),
                port=port,
            )
        key_type = KeyType.ED25519
        use_passphrase = False
        if not decision.reuse_key:
            if not c.confirm(
                "Koristiti preporučeni tip ključa Ed25519? (odgovorite 'n' za RSA 4096 za starije servere)",
                default=True,
            ):
                key_type = KeyType.RSA
            use_passphrase = self._ask_passphrase()
        if spec is None:
            config_text = "zadržati postojeći upravljani blok"
        else:
            action = "zameniti" if decision.config_action == "replace" else "dodati"
            config_text = f"{action} 'Host {spec.alias}' -> {spec.user}@{spec.hostname}:{spec.port or 22}"
        self._print_plan(
            [
                ("Privatni ključ", f"{paths.private}" + (" (postojeći, bez izmena)" if decision.reuse_key else "")),
                ("Javni ključ", str(paths.public)),
                ("Tip ključa", "postojeći ključ" if decision.reuse_key else ("Ed25519" if key_type is KeyType.ED25519 else "RSA 4096")),
                ("Passphrase", self._passphrase_label(decision, use_passphrase)),
                ("SSH config", config_text),
            ]
        )
        if not c.confirm("Nastaviti?", default=True):
            c.info("Ništa nije promenjeno.")
            return
        report = StepReport()
        try:
            key_paths = self._prepare_key_and_config(decision, spec, key_type, use_passphrase, report)
            if key_paths is None:
                report.add(STEP_CONFIG, StepStatus.SKIPPED, "generisanje ključa nije uspelo")
                return
            self._agent_step(key_paths, use_passphrase, report)
        finally:
            report.render(c)

        c.heading("Gde se nalaze vaši ključevi")
        self._print_storage(key_paths)
        c.heading("Instalacija javnog ključa na server")
        c.info(
            "Server mora da ima JAVNI ključ u fajlu ~/.ssh/authorized_keys ciljnog korisnika.\n"
            "Ovaj alat ne menja servere. Ključ možete sami instalirati, na primer iz PowerShell-a\n"
            "(biće vam tražena postojeća lozinka za server):"
        )
        target = f"{spec.user}@{spec.hostname}" if spec else "USER@HOST"
        port_option = f"-p {spec.port} " if spec and spec.port else ""
        c.info(
            f'  type "{key_paths.public}" | ssh {port_option}{target} '
            '"umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"'
        )
        self._offer_public_key(key_paths, "Prikazati JAVNI ključ sada?")
        c.heading("Napomena o ssh-agent-u")
        c.info(AGENT_NOTE)
        if report.status_of(STEP_CONFIG) in (StepStatus.OK, StepStatus.SKIPPED) and c.confirm(
            f"Testirati vezu ka '{decision.name}' sada? (uspeće tek kada javni ključ bude instaliran na serveru)",
            default=False,
        ):
            self.test_server(decision.name)

    # ----- 3. List ----------------------------------------------------------------

    def list_managed(self) -> None:
        c = self.console
        c.heading("Upravljani SSH ključevi i konfiguracije")
        c.info(f"Direktorijum ključeva: {self.env.ssh_dir}")
        c.info(
            f"SSH config:            {self.env.config_path}"
            + ("" if self.env.config_path.exists() else " (još ne postoji)")
        )
        document = self.config.load()
        blocks = document.managed_blocks()
        if not blocks:
            c.info("Još nema upravljanih unosa. Koristite opciju 1 ili 2 u meniju da biste ga napravili.")
        public_keys: dict[str, Path] = {}
        for block in blocks:
            c.print()
            c.print(f"  {block.alias}  ({block.kind})")
            c.info(f"    HostName:       {block.options.get('hostname', '?')}")
            c.info(f"    User:           {block.options.get('user', '?')}")
            c.info(f"    Port:           {block.options.get('port', '22')}")
            identity = block.options.get("identityfile")
            if identity:
                private = expand_identity_path(identity, self.env.home)
                public = private.with_name(private.name + ".pub")
                c.info(f"    IdentityFile:   {identity}")
                c.info(f"    Privatni ključ: {private} ({'postoji' if private.exists() else 'NEDOSTAJE'})")
                c.info(f"    Javni ključ:    {public} ({'postoji' if public.exists() else 'NEDOSTAJE'})")
                if public.exists():
                    public_keys[block.alias.casefold()] = public
                    fingerprint = self.keys.fingerprint(public)
                    if fingerprint:
                        c.info(f"    Otisak:         {fingerprint}")
            if block.kind == HostKind.GITHUB:
                c.info(f"    Git remote:     {github_remote_url(block.alias, 'OWNER', 'REPOSITORY')}")
        others = document.unmanaged_aliases()
        if others:
            c.print()
            c.info(f"Ostali Host unosi (ovaj alat ih ne upravlja i nikada ih ne menja): {', '.join(others)}")
        if public_keys:
            c.print()
            alias = c.ask("Unesite alias da biste prikazali njegov JAVNI ključ (prazno za povratak)")
            if alias:
                public = public_keys.get(alias.casefold())
                if public is None:
                    c.error(f"Ne postoji upravljani javni ključ za '{alias}'.")
                    return
                try:
                    text = read_public_key(public)
                except SSHManagerError as exc:
                    c.error(str(exc))
                    return
                c.print(f"JAVNI ključ ({public}) - bezbedno ga je deliti:")
                c.print(text)

    # ----- 4. Test ----------------------------------------------------------------

    def test_connection(self) -> None:
        c = self.console
        c.heading("Testiranje SSH veze")
        if not self.tools.ssh:
            c.error("ssh nije pronađen.\n" + OPENSSH_INSTALL_HINT)
            return
        blocks = self.config.load().managed_blocks()
        options = [(block.alias, f"{block.alias} ({block.kind})") for block in blocks]
        options += [
            ("__other__", "Drugi host alias iz SSH config fajla"),
            ("__back__", "Nazad u glavni meni"),
        ]
        choice = c.choose("Izaberite unos", options)
        if choice == "__back__":
            return
        if choice == "__other__":
            alias = c.ask_validated("Host alias", validate_alias_token)
            is_github = c.confirm("Da li je ovo GitHub alias?", default=False)
        else:
            alias = choice
            is_github = next(b.kind for b in blocks if b.alias == choice) == HostKind.GITHUB
        if is_github:
            self.test_github(alias)
        else:
            self.test_server(alias)

    def test_github(self, alias: str) -> ConnectionResult | None:
        c = self.console
        if not self.tools.ssh:
            c.error("ssh nije pronađen.\n" + OPENSSH_INSTALL_HINT)
            return None
        validate_alias_token(alias)
        c.info("GitHub ne pruža pristup shell-u. Uspešan test ispisuje pozdravnu poruku i prekida vezu.")
        if known_host_present(self.runner, self.tools.ssh_keygen, GITHUB_HOST) is False:
            c.info("github.com još nije u vašem known_hosts fajlu. Ako SSH zatraži potvrdu host ključa,")
            c.info("otkucajte 'yes' samo ako se otisak poklapa sa jednim od GitHub-ovih objavljenih otisaka:")
            for key_type, fingerprint in GITHUB_HOST_KEY_FINGERPRINTS:
                c.info(f"  {key_type:<8} {fingerprint}")
            c.info(f"  Izvor: {GITHUB_FINGERPRINTS_URL}")
        args = [self.tools.ssh, "-T", "-o", f"ConnectTimeout={CONNECT_TIMEOUT_SECONDS}", f"{GITHUB_SSH_USER}@{alias}"]
        c.info(f"Pokrećem: ssh -T git@{alias}")
        stream = self.runner.stream(args, on_line=lambda line: c.info(f"  | {redact(line)}"))
        result = interpret_github_ssh(stream.output, stream.returncode)
        self._print_connection_result(result)
        return result

    def test_server(self, alias: str) -> ConnectionResult | None:
        c = self.console
        if not self.tools.ssh:
            c.error("ssh nije pronađen.\n" + OPENSSH_INSTALL_HINT)
            return None
        validate_alias_token(alias)
        resolved = self.config.resolve(alias)
        if resolved:
            user = (resolved.get("user") or ["?"])[0]
            host = (resolved.get("hostname") or ["?"])[0]
            port = (resolved.get("port") or ["22"])[0]
            c.info(f"Testiram '{alias}' -> {user}@{host}:{port}")
        c.info(
            "Nijedna komanda se ne izvršava na serveru: ssh obavlja samo autentifikaciju (-N)\n"
            "i veza se odmah zatvara."
        )
        args = [self.tools.ssh, "-v", "-N", "-o", f"ConnectTimeout={CONNECT_TIMEOUT_SECONDS}", alias]

        def show(line: str) -> None:
            if not line.startswith("debug"):
                c.info(f"  | {redact(line)}")

        stream = self.runner.stream(args, on_line=show, stop_when=lambda line: bool(_SERVER_AUTH_RE.search(line)))
        result = interpret_server_ssh(stream)
        self._print_connection_result(result)
        return result

    def _print_connection_result(self, result: ConnectionResult) -> None:
        if result.success and not result.deploy_key:
            self.console.ok(result.summary)
        elif result.success:
            self.console.warn(result.summary)
        else:
            self.console.error(result.summary)
        for hint in result.hints:
            self.console.info(f"- {hint}")

    # ----- --check ------------------------------------------------------------------

    def check_dependencies(self) -> int:
        c = self.console
        c.print(f"SSH Key Manager {__version__} - provera zavisnosti")
        c.info(f"Python      {platform.python_version()} ({sys.executable})")
        c.info(f"OS          {platform.system()} {platform.release()} ({platform.version()})")
        required_ok = True
        for name, path, required, hint in (
            ("ssh-keygen", self.tools.ssh_keygen, True, OPENSSH_INSTALL_HINT),
            ("ssh", self.tools.ssh, True, OPENSSH_INSTALL_HINT),
            ("ssh-add", self.tools.ssh_add, False, OPENSSH_INSTALL_HINT),
            ("gh", self.tools.gh, False, GH_INSTALL_HINT),
            ("git", self.tools.git, False, GIT_INSTALL_HINT),
        ):
            if path:
                c.ok(f"{name:<11} {path}")
            else:
                (c.error if required else c.warn)(
                    f"{name:<11} nije pronađen ({'obavezan' if required else 'opcioni'})\n{hint}"
                )
                required_ok = required_ok and not required
        if self.gh.available:
            version = self.gh.version()
            if version:
                c.info(f"GitHub CLI  {version}")
            try:
                status = self.gh.auth_status()
            except CommandError as exc:
                c.warn(f"Nije moguće proveriti GitHub prijavu: {exc}")
            else:
                if status.logged_in:
                    scope = {
                        True: "da",
                        False: f"ne (pokrenite: {GH_REFRESH_COMMAND})",
                        None: "nepoznato",
                    }[status.has_key_scope()]
                    c.ok(f"GitHub CLI je prijavljen kao '{status.account}'. Može da dodaje SSH ključeve: {scope}")
                else:
                    c.warn(f"GitHub CLI nije prijavljen. Pokrenite: {GH_LOGIN_COMMAND}")
        state = agent_state(self.runner, self.tools.ssh_add)
        (c.ok if state is AgentState.RUNNING else c.warn)(f"ssh-agent   {state}")
        if state is not AgentState.RUNNING:
            c.info(AGENT_NOTE)
        return 0 if required_ok else 1


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):  # type: ignore[no-untyped-def]
        return super().add_usage(usage, actions, groups, "upotreba: " if prefix is None else prefix)


_ARGPARSE_MESSAGES = (
    ("unrecognized arguments:", "nepoznati argumenti:"),
    ("ambiguous option:", "dvosmislena opcija:"),
    ("ignored explicit argument", "zanemaren eksplicitni argument"),
    ("expected one argument", "očekivan je jedan argument"),
)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str):  # type: ignore[override]
        for english, serbian in _ARGPARSE_MESSAGES:
            message = message.replace(english, serbian)
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: greška: {message}\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="ssh_manager.py",
        description=(
            "Interaktivni menadžer SSH ključeva za Windows: generiše SSH ključeve pomoću OpenSSH-a, "
            "održava upravljane blokove u ~/.ssh/config, registruje GitHub ključeve za "
            "autentifikaciju preko GitHub CLI-ja i testira veze."
        ),
        epilog=(
            "Bez opcija otvara se interaktivni meni:\n"
            "  python ssh_manager.py\n\n"
            "Ključevi se čuvaju u %USERPROFILE%\\.ssh. Privatni ključevi nikada ne napuštaju ovaj računar."
        ),
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    parser._optionals.title = "opcije"
    parser.add_argument("-h", "--help", action="help", help="prikaži ovu pomoć i izađi")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
        help="prikaži verziju programa i izađi",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="proveri zavisnosti, GitHub CLI prijavu i ssh-agent, pa izađi",
    )
    return parser


def _configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(Exception):
            # A real Windows console handles Unicode natively. Git Bash (mintty) and
            # redirected output expect UTF-8, which Serbian letters (č, ć, š, ž, đ) need.
            if os.name == "nt" and not stream.isatty():
                reconfigure(encoding="utf-8", errors="replace")
            else:
                reconfigure(errors="replace")


def main(
    argv: Sequence[str] | None = None,
    *,
    console: Console | None = None,
    runner: CommandRunner | None = None,
    tools: Tools | None = None,
    env: Environment | None = None,
) -> int:
    _configure_output()
    args = build_arg_parser().parse_args(argv)
    console = console or Console()
    app = App(console, runner or CommandRunner(), tools or Tools.discover(), env or Environment.default())
    try:
        if args.check:
            return app.check_dependencies()
        return app.run()
    except KeyboardInterrupt:
        console.print()
        console.warn("Prekinuto.")
        return 130
    except SSHManagerError as exc:
        console.error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
