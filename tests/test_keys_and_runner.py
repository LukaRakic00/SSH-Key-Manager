import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import PUBLIC_KEY, FakeRunner, ok, sm


class KeyManagerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ssh_dir = Path(tmp.name) / ".ssh"

        def keygen(argv, interactive):
            if "-t" in argv:
                private = Path(argv[argv.index("-f") + 1])
                private.write_text("PRIVATE")
                Path(str(private) + ".pub").write_text(PUBLIC_KEY + "\n")
            return ok(argv, "256 SHA256:abc test (ED25519)\n" if "-l" in argv else "")

        self.runner = FakeRunner(handler=keygen)
        self.keys = sm.KeyManager(self.ssh_dir, self.runner, "ssh-keygen")

    def test_paths_stay_inside_ssh_dir(self):
        paths = self.keys.paths("github-work")
        self.assertEqual(paths.private, self.ssh_dir / "github-work")
        self.assertEqual(paths.public, self.ssh_dir / "github-work.pub")
        with self.assertRaises(sm.ValidationError):
            self.keys.paths("../outside")

    def test_generate_without_passphrase(self):
        paths = self.keys.generate("github-work", sm.KeyType.ED25519, use_passphrase=False)
        self.assertTrue(paths.private.is_file() and paths.public.is_file())
        argv = self.runner.calls[0].argv
        self.assertEqual(argv[:3], ["ssh-keygen", "-t", "ed25519"])
        self.assertEqual(argv[-2:], ["-N", ""])
        self.assertIn(str(paths.private), argv)
        self.assertFalse(self.runner.calls[0].interactive)

    def test_generate_with_passphrase_is_interactive_and_passphrase_never_in_argv(self):
        self.keys.generate("srv", sm.KeyType.RSA, use_passphrase=True)
        call = self.runner.calls[0]
        self.assertTrue(call.interactive)
        self.assertNotIn("-N", call.argv)
        self.assertIn("4096", call.argv)

    def test_never_overwrites_existing_files(self):
        self.ssh_dir.mkdir()
        (self.ssh_dir / "github-work.pub").write_text("existing")
        with self.assertRaises(sm.KeyExistsError):
            self.keys.generate("github-work", sm.KeyType.ED25519, use_passphrase=False)
        self.assertEqual(self.runner.calls, [])
        self.assertEqual((self.ssh_dir / "github-work.pub").read_text(), "existing")

    def test_failure_is_reported_and_partial_files_are_kept(self):
        def failing(argv, interactive):
            Path(argv[argv.index("-f") + 1]).write_text("PRIVATE")
            return ok(argv, stderr="disk full", code=1)

        keys = sm.KeyManager(self.ssh_dir, FakeRunner(handler=failing), "ssh-keygen")
        with self.assertRaises(sm.CommandError) as ctx:
            keys.generate("k", sm.KeyType.ED25519, use_passphrase=False)
        self.assertIn("izlazni kod 1", str(ctx.exception))
        self.assertTrue((self.ssh_dir / "k").exists())

    def test_missing_ssh_keygen(self):
        keys = sm.KeyManager(self.ssh_dir, FakeRunner(), None)
        with self.assertRaises(sm.CommandError) as ctx:
            keys.generate("k", sm.KeyType.ED25519, use_passphrase=False)
        self.assertIn("OpenSSH", str(ctx.exception))

    def test_fingerprint(self):
        self.assertEqual(self.keys.fingerprint(Path("x.pub")), "256 SHA256:abc test (ED25519)")

    @unittest.skipUnless(os.name == "nt", "Windows-specific")
    def test_windows_permissions_use_icacls_argument_list(self):
        runner = FakeRunner()
        keys = sm.KeyManager(self.ssh_dir, runner, "ssh-keygen", icacls="icacls")
        with mock.patch.dict(os.environ, {"USERNAME": "alice", "USERDOMAIN": "PC"}):
            success, _ = keys.restrict_permissions(Path("C:/k"))
        self.assertTrue(success)
        self.assertEqual(runner.calls[0].argv, ["icacls", str(Path("C:/k")), "/inheritance:r", "/grant:r", "PC\\alice:F"])

    def test_read_public_key_validation(self):
        self.ssh_dir.mkdir()
        good = self.ssh_dir / "a.pub"
        good.write_text(PUBLIC_KEY + "\r\n")
        self.assertEqual(sm.read_public_key(good), PUBLIC_KEY)
        bad = self.ssh_dir / "b.pub"
        bad.write_text("not a key")
        with self.assertRaises(sm.ValidationError):
            sm.read_public_key(bad)
        with self.assertRaises(sm.ValidationError):
            sm.read_public_key(self.ssh_dir / "a")


class AgentAndKnownHostsTests(unittest.TestCase):
    def test_agent_state_from_exit_codes(self):
        for code, state in ((0, sm.AgentState.RUNNING), (1, sm.AgentState.RUNNING),
                            (2, sm.AgentState.NOT_RUNNING), (9, sm.AgentState.UNKNOWN)):
            with self.subTest(code=code):
                runner = FakeRunner(handler=lambda argv, _i, c=code: ok(argv, code=c))
                self.assertEqual(sm.agent_state(runner, "ssh-add"), state)
        self.assertEqual(sm.agent_state(FakeRunner(), None), sm.AgentState.UNKNOWN)

    def test_known_host_present(self):
        runner = FakeRunner(handler=lambda argv, _i: ok(argv, code=1))
        self.assertFalse(sm.known_host_present(runner, "ssh-keygen", "github.com"))
        runner = FakeRunner(handler=lambda argv, _i: ok(argv, "github.com ssh-ed25519 AAAA"))
        self.assertTrue(sm.known_host_present(runner, "ssh-keygen", "github.com"))


class ServerConnectionInterpretationTests(unittest.TestCase):
    def test_success_when_stopped_after_authentication(self):
        result = sm.interpret_server_ssh(sm.StreamResult(None, ["debug1: Authenticated to h ([1.2.3.4]:22) using \"publickey\"."], True))
        self.assertTrue(result.success)

    def test_failure(self):
        result = sm.interpret_server_ssh(sm.StreamResult(255, ["deploy@h: Permission denied (publickey)."]))
        self.assertFalse(result.success)
        self.assertTrue(any("authorized_keys" in h for h in result.hints))

    def test_timeout(self):
        result = sm.interpret_server_ssh(sm.StreamResult(None, [], timed_out=True))
        self.assertFalse(result.success)


class CommandRunnerTests(unittest.TestCase):
    def test_never_uses_shell(self):
        with mock.patch.object(sm.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            sm.CommandRunner().run(["prog", "a b; rm -rf /"])
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["prog", "a b; rm -rf /"])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_missing_program(self):
        with self.assertRaises(sm.CommandError):
            sm.CommandRunner().run(["definitely-not-a-real-program-xyz"])

    def test_rejects_nul_bytes(self):
        with self.assertRaises(sm.CommandError):
            sm.CommandRunner().run(["prog", "a\x00b"])

    def test_timeout_is_reported(self):
        with mock.patch.object(sm.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 1)):
            with self.assertRaises(sm.CommandError) as ctx:
                sm.CommandRunner().run(["prog"], timeout=1)
        self.assertIn("nije završila", str(ctx.exception))

    def test_real_process_round_trip(self):
        result = sm.CommandRunner().run([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"])
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout.strip(), "out")
        self.assertEqual(result.stderr.strip(), "err")

    def test_stream_stops_when_condition_matches(self):
        code = "import time\nprint('one', flush=True)\nprint('AUTH', flush=True)\ntime.sleep(30)\n"
        seen = []
        result = sm.CommandRunner().stream([sys.executable, "-c", code], on_line=seen.append,
                                           stop_when=lambda line: line == "AUTH", timeout=20)
        self.assertTrue(result.stopped_early)
        self.assertEqual(seen, ["one", "AUTH"])


if __name__ == "__main__":
    unittest.main()
