"""Test doubles: no real ssh, ssh-keygen, ssh-add or gh process is ever started."""

from __future__ import annotations

import io
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ssh_manager as sm  # noqa: E402

PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGVrZXlib2R5Zm9ydGVzdHM= test@pc"
PUBLIC_KEY_BODY = "AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGVrZXlib2R5Zm9ydGVzdHM="
PRIVATE_MARKER = "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET-CONTENT\n-----END OPENSSH PRIVATE KEY-----\n"


@dataclass
class Call:
    argv: list[str]
    interactive: bool = False
    env_overrides: dict[str, str] | None = None
    streamed: bool = False


Handler = Callable[[list[str], bool], "sm.CommandResult | Exception"]


@dataclass
class FakeRunner(sm.CommandRunner):
    handler: Handler | None = None
    stream_handler: Callable[[list[str]], tuple[list[str], int]] | None = None
    calls: list[Call] = field(default_factory=list)

    def run(self, args, *, interactive=False, timeout=None, env_overrides=None):  # type: ignore[override]
        argv = [os.fspath(a) for a in args]
        self.calls.append(Call(argv, interactive, dict(env_overrides) if env_overrides else None))
        if self.handler is None:
            return sm.CommandResult(tuple(argv), 0)
        result = self.handler(argv, interactive)
        if isinstance(result, Exception):
            raise result
        return result

    def stream(self, args, *, on_line, stop_when=None, timeout=0):  # type: ignore[override]
        argv = [os.fspath(a) for a in args]
        self.calls.append(Call(argv, streamed=True))
        lines, code = self.stream_handler(argv) if self.stream_handler else ([], 255)
        stopped = False
        seen = []
        for line in lines:
            seen.append(line)
            on_line(line)
            if stop_when and stop_when(line):
                stopped = True
                break
        return sm.StreamResult(None if stopped else code, seen, stopped)

    def programs(self) -> list[str]:
        return [Path(call.argv[0]).name for call in self.calls]

    def find(self, *words: str) -> list[Call]:
        return [c for c in self.calls if all(w in c.argv for w in words)]


class ScriptedInput:
    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise AssertionError(f"Unexpected prompt with no scripted answer: {prompt!r}")
        return self.answers.pop(0)


def make_console(answers: list[str]) -> tuple[sm.Console, io.StringIO, ScriptedInput]:
    out = io.StringIO()
    scripted = ScriptedInput(answers)
    return sm.Console(input_func=scripted, out=out), out, scripted


def ok(argv: list[str], stdout: str = "", stderr: str = "", code: int = 0) -> sm.CommandResult:
    return sm.CommandResult(tuple(argv), code, stdout, stderr)


FAKE_TOOLS = sm.Tools(ssh="ssh", ssh_keygen="ssh-keygen", ssh_add="ssh-add", gh="gh", git=None, icacls=None)


def make_env(home: Path) -> sm.Environment:
    ssh_dir = home / ".ssh"
    return sm.Environment(home=home, ssh_dir=ssh_dir, config_path=ssh_dir / "config")


GH_STATUS_OK = """github.com
  ✓ Logged in to github.com account octocat (keyring)
  - Active account: true
  - Git operations protocol: ssh
  - Token: gho_************************************
  - Token scopes: 'gist', 'read:org', 'repo', 'write:public_key'
"""

GH_STATUS_NO_SCOPE = GH_STATUS_OK.replace(", 'write:public_key'", "")

GH_STATUS_LOGGED_OUT = "You are not logged into any GitHub hosts. To log in, run: gh auth login\n"


class FakeSystem:
    """Simulates ssh-keygen, ssh -G, ssh-add and gh against a temporary home directory."""

    def __init__(self, env: sm.Environment) -> None:
        self.env = env
        self.auth_outputs = [GH_STATUS_OK]
        self.add_result: tuple[int, str, str] = (0, "✓ Public key added to your account\n", "")
        self.list_type = "authentication"
        self.agent_code = 2
        self.keygen_code = 0

    def resolve(self, alias: str) -> str:
        text = self.env.config_path.read_text(encoding="utf-8") if self.env.config_path.exists() else ""
        block = sm.SSHConfigDocument(text).managed_block(alias)
        if block is None:
            return f"hostname {alias}\nuser someone\nport 22\nidentitiesonly no\nidentityfile ~/.ssh/id_ed25519\n"
        o = block.options
        return (
            f"hostname {o['hostname']}\nuser {o['user']}\nport {o.get('port', '22')}\n"
            f"identitiesonly {o['identitiesonly']}\nidentityfile {o['identityfile']}\n"
        )

    def __call__(self, argv: list[str], interactive: bool) -> sm.CommandResult:
        prog, args = Path(argv[0]).name, argv[1:]
        if prog == "ssh-keygen" and "-t" in args:
            if self.keygen_code:
                return ok(argv, stderr="ssh-keygen: failure", code=self.keygen_code)
            private = Path(args[args.index("-f") + 1])
            private.write_text(PRIVATE_MARKER, encoding="utf-8")
            private.with_name(private.name + ".pub").write_text(PUBLIC_KEY + "\n", encoding="utf-8")
            return ok(argv, "Your identification has been saved\n")
        if prog == "ssh-keygen" and "-l" in args:
            return ok(argv, "256 SHA256:fakefingerprint test@pc (ED25519)\n")
        if prog == "ssh-keygen" and "-F" in args:
            return ok(argv, "# Host github.com found\n|1|hashed ssh-ed25519 AAAA\n")
        if prog == "ssh" and "-G" in args:
            return ok(argv, self.resolve(args[-1]))
        if prog == "ssh-add":
            return ok(argv, code=self.agent_code)
        if prog == "gh" and args == ["--version"]:
            return ok(argv, "gh version 2.80.0 (2026-01-01)\n")
        if prog == "gh" and args[:2] == ["auth", "status"]:
            output = self.auth_outputs.pop(0) if len(self.auth_outputs) > 1 else self.auth_outputs[0]
            code = 0 if "Logged in" in output else 1
            return ok(argv, stderr=output, code=code)
        if prog == "gh" and args[:2] in (["auth", "login"], ["auth", "refresh"]):
            return ok(argv)
        if prog == "gh" and args[:2] == ["ssh-key", "add"]:
            code, out, err = self.add_result
            return ok(argv, out, err, code)
        if prog == "gh" and args[:2] == ["ssh-key", "list"]:
            listing = f"github-work\t{PUBLIC_KEY}\t2026-10-28T10:00:00Z\t123\t{self.list_type}\n"
            return ok(argv, listing)
        raise AssertionError(f"Unexpected command: {argv}")
