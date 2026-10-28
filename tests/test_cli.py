import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path

from tests.helpers import (FAKE_TOOLS, GH_STATUS_LOGGED_OUT, GH_STATUS_NO_SCOPE, GH_STATUS_OK, PUBLIC_KEY,
                           FakeRunner, FakeSystem, make_console, make_env, sm)


class CLITestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.env = make_env(self.home)
        self.system = FakeSystem(self.env)
        self.runner = FakeRunner(handler=self.system)

    def run_cli(self, answers, argv=(), tools=FAKE_TOOLS):
        console, out, scripted = make_console(answers)
        code = sm.main(list(argv), console=console, runner=self.runner, tools=tools, env=self.env)
        self.assertEqual(scripted.answers, [], "not all scripted answers were used")
        return code, out.getvalue()

    def assert_step(self, output, status, text):
        self.assertRegex(output, rf"\[{status}\]\s+{re.escape(text)}")


class ArgumentTests(unittest.TestCase):
    def test_help(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), self.assertRaises(SystemExit) as ctx:
            sm.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        text = buffer.getvalue()
        self.assertIn("--check", text)
        self.assertIn("upotreba:", text)
        self.assertIn("opcije", text)
        self.assertIn("prikaži ovu pomoć i izađi", text)

    def test_unknown_argument_error_is_in_serbian(self):
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer), self.assertRaises(SystemExit) as ctx:
            sm.main(["--nepostojeca-opcija"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("greška: nepoznati argumenti: --nepostojeca-opcija", buffer.getvalue())

    def test_version(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), self.assertRaises(SystemExit):
            sm.main(["--version"])
        self.assertIn(sm.__version__, buffer.getvalue())


class ConfirmTests(unittest.TestCase):
    def test_serbian_and_english_answers(self):
        for answer, expected in (("d", True), ("DA", True), ("y", True), ("n", False), ("ne", False),
                                 ("no", False), ("", True)):
            with self.subTest(answer=answer):
                console, _, _ = make_console([answer])
                self.assertEqual(console.confirm("Pitanje?", default=True), expected)

    def test_invalid_answer_is_reprompted(self):
        console, out, scripted = make_console(["možda", "ne"])
        self.assertFalse(console.confirm("Pitanje?", default=True))
        self.assertIn("Odgovorite sa 'd' (da) ili 'n' (ne).", out.getvalue())
        self.assertIn("Pitanje? [D/n]: ", scripted.prompts[0])


class MenuTests(CLITestCase):
    def test_menu_shows_options_and_exits(self):
        code, output = self.run_cli(["5"])
        self.assertEqual(code, 0)
        for text in ("1. Kreiraj SSH ključ za GitHub", "2. Kreiraj SSH ključ za udaljeni server",
                     "3. Prikaži upravljane SSH ključeve i konfiguracije", "4. Testiraj SSH vezu",
                     "5. Izlaz"):
            self.assertIn(text, output)

    def test_invalid_choice(self):
        code, output = self.run_cli(["9", "abc", "5"])
        self.assertEqual(code, 0)
        self.assertEqual(output.count("Neispravan izbor"), 2)

    def test_end_of_input_exits_cleanly(self):
        console = sm.Console(input_func=lambda _p: (_ for _ in ()).throw(EOFError()), out=io.StringIO())
        self.assertEqual(sm.main([], console=console, runner=self.runner, tools=FAKE_TOOLS, env=self.env), 0)

    def test_missing_openssh_is_explained(self):
        tools = sm.Tools(ssh=None, ssh_keygen=None, ssh_add=None, gh=None, git=None)
        code, output = self.run_cli(["1", "5"], tools=tools)
        self.assertIn("Add-WindowsCapability -Online -Name OpenSSH.Client", output)
        self.assertEqual(self.runner.calls, [])

    def test_list_with_no_entries(self):
        code, output = self.run_cli(["3", "5"])
        self.assertIn("Još nema upravljanih unosa", output)

    def test_check_command(self):
        code, output = self.run_cli([], argv=["--check"])
        self.assertEqual(code, 0)
        self.assertIn("octocat", output)
        self.assertIn("Može da dodaje SSH ključeve: da", output)


class GitHubFlowTests(CLITestCase):
    # menu, name, accept "github-" prefix, no passphrase, proceed, owner/repo, skip test, exit
    ANSWERS = ["1", "work", "y", "n", "y", "octo/hello", "n", "5"]

    def test_full_github_flow(self):
        code, output = self.run_cli(self.ANSWERS)
        self.assertEqual(code, 0)
        private = self.env.ssh_dir / "github-work"
        self.assertTrue(private.is_file())
        config = self.env.config_path.read_text()
        self.assertIn("Host github-work\n", config)
        self.assertIn("IdentityFile ~/.ssh/github-work\n", config)

        add = self.runner.find("ssh-key", "add")
        self.assertEqual(len(add), 1)
        self.assertEqual(add[0].argv, ["gh", "ssh-key", "add", str(private) + ".pub", "--type", "authentication",
                                       "--title", "github-work"])
        self.assertEqual(len(self.runner.find("ssh-key", "list")), 1)
        self.assert_step(output, "OK", "Registracija ključa na GitHub-u")
        self.assertIn("naveden je na vašem nalogu kao ključ za autentifikaciju", output)
        self.assertIn("git clone git@github-work:octo/hello.git", output)
        self.assertNotIn("github-github", output + config)
        self.assertIn("ne daje pristup repozitorijumima", output)
        self.assertIn("'AddKeysToAgent yes' dodaje ključ samo u ssh-agent koji je već pokrenut", output)
        self.assertNotIn("SECRET-CONTENT", output)
        self.assertNotIn(PUBLIC_KEY, output)  # public key only shown on request

    def test_alias_with_prefix_is_used_unchanged(self):
        code, output = self.run_cli(["1", "github-work", "n", "y", "", "n", "5"])
        self.assertNotIn("github-github-work", output)
        self.assertTrue((self.env.ssh_dir / "github-work").exists())

    def test_upload_failure_is_reported_and_nothing_is_rolled_back(self):
        self.system.add_result = (1, "", "HTTP 422: Validation Failed\nkey is already in use")
        # ... same as above plus "display public key?" -> yes
        code, output = self.run_cli(["1", "github-work", "n", "y", "y", "", "n", "5"])
        self.assert_step(output, "NEUSPEH", "Registracija ključa na GitHub-u: NIJE otpremljen")
        self.assertIn("Isti ključ može biti registrovan na GitHub-u samo jednom", output)
        self.assertNotIn("dodat kao ključ za autentifikaciju", output)
        self.assertEqual(self.runner.find("ssh-key", "list"), [])
        self.assert_step(output, "OK", "Generisanje SSH ključa")
        self.assertTrue((self.env.ssh_dir / "github-work").exists())
        self.assertIn("Host github-work", self.env.config_path.read_text())
        self.assertIn("JAVNI ključ (", output)
        self.assertIn(PUBLIC_KEY, output)

    def test_not_logged_in_and_login_declined_changes_nothing(self):
        self.system.auth_outputs = [GH_STATUS_LOGGED_OUT]
        code, output = self.run_cli(["1", "n", "n", "5"])
        self.assertIn("Ništa nije promenjeno", output)
        self.assertNotIn("ssh-keygen", self.runner.programs())
        self.assertFalse(self.env.config_path.exists())

    def test_browser_login_is_offered(self):
        self.system.auth_outputs = [GH_STATUS_LOGGED_OUT, GH_STATUS_OK]
        code, output = self.run_cli(["1", "y", "github-work", "n", "y", "", "n", "5"])
        login = self.runner.find("auth", "login")
        self.assertEqual(len(login), 1)
        self.assertTrue(login[0].interactive)
        self.assertIn("--skip-ssh-key", login[0].argv)
        self.assertIn("Prijavljeni ste na github.com kao 'octocat'", output)

    def test_missing_scope_triggers_refresh(self):
        self.system.auth_outputs = [GH_STATUS_NO_SCOPE, GH_STATUS_OK]
        code, output = self.run_cli(["1", "y", "github-work", "n", "y", "", "n", "5"])
        refresh = self.runner.find("auth", "refresh")
        self.assertEqual(len(refresh), 1)
        self.assertIn("write:public_key", refresh[0].argv)
        self.assertIn("Potreban je scope 'write:public_key'", output)

    def test_gh_missing_offers_manual_registration(self):
        tools = sm.Tools(ssh="ssh", ssh_keygen="ssh-keygen", ssh_add="ssh-add", gh=None, git=None)
        code, output = self.run_cli(["1", "y", "github-work", "n", "y", "n", "", "n", "5"], tools=tools)
        self.assertIn("winget install --id GitHub.cli", output)
        self.assert_step(output, "PRESKOČENO", "Registracija ključa na GitHub-u")
        self.assertNotIn("gh", self.runner.programs())

    def test_existing_key_is_never_overwritten(self):
        self.env.ssh_dir.mkdir()
        (self.env.ssh_dir / "github-work").write_text("OLD PRIVATE")
        (self.env.ssh_dir / "github-work.pub").write_text(PUBLIC_KEY + "\n")
        # choose "different name", then a new one
        code, output = self.run_cli(["1", "github-work", "1", "github-home", "n", "y", "", "n", "5"])
        self.assertEqual((self.env.ssh_dir / "github-work").read_text(), "OLD PRIVATE")
        self.assertTrue((self.env.ssh_dir / "github-home").exists())

    def test_unmanaged_duplicate_alias_is_rejected(self):
        self.env.ssh_dir.mkdir()
        original = "Host github-work\n    HostName github.com\n    IdentityFile ~/.ssh/other\n"
        self.env.config_path.write_text(original)
        code, output = self.run_cli(["1", "github-work", "github-alt", "n", "y", "", "n", "5"])
        self.assertIn("ovaj alat ne upravlja", output)
        text = self.env.config_path.read_text()
        self.assertIn(original, text)
        self.assertIn("Host github-alt", text)

    def test_connection_test_after_setup(self):
        self.runner.stream_handler = lambda argv: (
            ["Hi octocat! You've successfully authenticated, but GitHub does not provide shell access."], 1)
        code, output = self.run_cli(["1", "github-work", "n", "y", "", "y", "5"])
        streamed = [c for c in self.runner.calls if c.streamed]
        self.assertEqual(streamed[0].argv, ["ssh", "-T", "-o", "ConnectTimeout=15", "git@github-work"])
        self.assertIn("GitHub je potvrdio ovaj ključ za korisnika 'octocat'", output)


class ServerFlowTests(CLITestCase):
    def test_full_server_flow(self):
        answers = ["2", "prod", "203.0.113.10", "deploy", "2222", "y", "n", "y", "n", "n", "5"]
        code, output = self.run_cli(answers)
        config = self.env.config_path.read_text()
        for line in ("Host prod\n", "HostName 203.0.113.10\n", "User deploy\n", "Port 2222\n",
                     "IdentityFile ~/.ssh/prod\n", "IdentitiesOnly yes\n"):
            self.assertIn(line, config)
        self.assert_step(output, "OK", "Provera SSH config fajla (ssh -G)")
        self.assertIn("Ovaj alat ne menja servere", output)
        self.assertNotIn("gh", self.runner.programs())

    def test_invalid_inputs_are_reprompted(self):
        answers = ["2", "../prod", "prod", "bad host", "203.0.113.10", "-root", "deploy", "70000", "",
                   "y", "n", "y", "n", "n", "5"]
        code, output = self.run_cli(answers)
        self.assertIn("separatore putanje", output)
        self.assertIn("ispravno ime hosta", output)
        self.assertIn("ispravno korisničko ime", output)
        self.assertIn("od 1 do 65535", output)
        self.assertNotIn("Port", self.env.config_path.read_text())

    def test_replace_existing_managed_block(self):
        self.run_cli(["2", "prod", "203.0.113.10", "deploy", "", "y", "n", "y", "n", "n", "5"])
        # Key exists -> reuse it; managed block exists -> replace and confirm.
        answers = ["2", "prod", "2", "3", "y", "198.51.100.7", "ops", "", "y", "n", "n", "5"]
        code, output = self.run_cli(answers)
        config = self.env.config_path.read_text()
        self.assertIn("HostName 198.51.100.7", config)
        self.assertNotIn("203.0.113.10", config)
        self.assertEqual(config.count("# BEGIN SSH-MANAGER prod"), 1)
        backups = list(self.env.ssh_dir.glob("config.ssh-manager-backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertIn("203.0.113.10", backups[0].read_text())

    def test_server_connection_test_never_runs_remote_command(self):
        self.run_cli(["2", "prod", "203.0.113.10", "deploy", "", "y", "n", "y", "n", "n", "5"])
        self.runner.stream_handler = lambda argv: (["debug1: Authenticated to 203.0.113.10 ([203.0.113.10]:22) using \"publickey\"."], 0)
        code, output = self.run_cli(["4", "1", "5"])
        streamed = [c for c in self.runner.calls if c.streamed][-1]
        self.assertEqual(streamed.argv, ["ssh", "-v", "-N", "-o", "ConnectTimeout=15", "prod"])
        self.assertIn("Autentifikacija je uspela", output)

    def test_list_shows_entries_and_public_key_on_request(self):
        self.run_cli(["2", "prod", "203.0.113.10", "deploy", "", "y", "n", "y", "n", "n", "5"])
        code, output = self.run_cli(["3", "prod", "5"])
        self.assertIn("prod  (server)", output)
        self.assertIn("HostName:       203.0.113.10", output)
        self.assertIn("JAVNI ključ (", output)
        self.assertIn(PUBLIC_KEY, output)
        self.assertNotIn("SECRET-CONTENT", output)


if __name__ == "__main__":
    unittest.main()
