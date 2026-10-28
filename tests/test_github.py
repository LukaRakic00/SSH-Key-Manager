import tempfile
import unittest
from pathlib import Path

from tests.helpers import (GH_STATUS_LOGGED_OUT, GH_STATUS_NO_SCOPE, GH_STATUS_OK, PUBLIC_KEY, FakeRunner, ok,
                           sm)

OLD_FORMAT = """github.com
  ✓ Logged in to github.com as octocat (oauth_token)
  ✓ Git operations for github.com configured to use ssh protocol.
  ✓ Token: *******************
  ✓ Token scopes: admin:public_key, gist, read:org, repo
"""

MULTI_ACCOUNT = """github.com
  ✓ Logged in to github.com account old-account (keyring)
  - Active account: false
  - Token scopes: 'repo'

  ✓ Logged in to github.com account current (keyring)
  - Active account: true
  - Token scopes: 'repo', 'admin:public_key'
"""

EXPIRED = """github.com
  X Failed to log in to github.com account octocat (keyring)
  - Active account: true
  - The token in keyring is invalid.
  - To re-authenticate, run: gh auth login -h github.com
"""

ENV_TOKEN = """github.com
  ✓ Logged in to github.com account bot (GH_TOKEN)
  - Active account: true
  - Token: ghp_************************************
  - Token scopes: 'repo'
"""

FINE_GRAINED = """github.com
  ✓ Logged in to github.com account octocat (keyring)
  - Active account: true
  - Token: github_pat_****************************
"""


class AuthStatusParsingTests(unittest.TestCase):
    def test_new_format(self):
        status = sm.parse_gh_auth_status(GH_STATUS_OK)
        self.assertTrue(status.logged_in)
        self.assertEqual(status.account, "octocat")
        self.assertEqual(status.token_source, "keyring")
        self.assertIn("write:public_key", status.scopes)
        self.assertTrue(status.has_key_scope())
        self.assertFalse(status.uses_env_token)

    def test_missing_scope(self):
        status = sm.parse_gh_auth_status(GH_STATUS_NO_SCOPE)
        self.assertFalse(status.has_key_scope())

    def test_read_only_scope_is_not_enough(self):
        status = sm.parse_gh_auth_status(GH_STATUS_NO_SCOPE.replace("'repo'", "'repo', 'read:public_key'"))
        self.assertFalse(status.has_key_scope())

    def test_old_format(self):
        status = sm.parse_gh_auth_status(OLD_FORMAT)
        self.assertTrue(status.logged_in)
        self.assertEqual(status.account, "octocat")
        self.assertTrue(status.has_key_scope())

    def test_active_account_is_used(self):
        status = sm.parse_gh_auth_status(MULTI_ACCOUNT)
        self.assertEqual(status.account, "current")
        self.assertTrue(status.has_key_scope())

    def test_not_logged_in(self):
        status = sm.parse_gh_auth_status(GH_STATUS_LOGGED_OUT)
        self.assertFalse(status.logged_in)
        self.assertIn("niste prijavljeni", status.problem)

    def test_expired_token(self):
        status = sm.parse_gh_auth_status(EXPIRED)
        self.assertFalse(status.logged_in)
        self.assertIn("invalid", status.problem)

    def test_env_token(self):
        status = sm.parse_gh_auth_status(ENV_TOKEN)
        self.assertTrue(status.uses_env_token)
        self.assertFalse(status.has_key_scope())

    def test_fine_grained_token_scopes_unknown(self):
        status = sm.parse_gh_auth_status(FINE_GRAINED)
        self.assertTrue(status.logged_in)
        self.assertIsNone(status.has_key_scope())


class ErrorClassificationTests(unittest.TestCase):
    def test_classification(self):
        cases = {
            "HTTP 422: Validation Failed (https://api.github.com/user/keys)\nkey is already in use": sm.GhErrorKind.DUPLICATE,
            "HTTP 404: Not Found\nThis API operation needs the \"admin:public_key\" scope.": sm.GhErrorKind.PERMISSION,
            "HTTP 403: Resource not accessible by integration": sm.GhErrorKind.PERMISSION,
            "HTTP 401: Bad credentials (https://api.github.com/user/keys)": sm.GhErrorKind.AUTH,
            "HTTP 403: Resource protected by organization SAML enforcement.": sm.GhErrorKind.POLICY,
            "error connecting to api.github.com\ndial tcp: lookup api.github.com: no such host": sm.GhErrorKind.NETWORK,
            "something odd happened": sm.GhErrorKind.UNKNOWN,
        }
        for text, kind in cases.items():
            with self.subTest(text=text):
                self.assertEqual(sm.classify_gh_error(text), kind)

    def test_every_kind_has_explanation(self):
        for kind in sm.GhErrorKind:
            self.assertTrue(sm.GH_ERROR_EXPLANATIONS[kind])


class GitHubCLITests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pub = Path(tmp.name) / "github-work.pub"
        self.pub.write_text(PUBLIC_KEY + "\n")

    def test_add_key_uses_exact_supported_command(self):
        runner = FakeRunner(handler=lambda argv, _i: ok(argv, "✓ Public key added to your account"))
        result = sm.GitHubCLI(runner, "gh").add_key(self.pub, "github-work")
        self.assertTrue(result.success)
        self.assertFalse(result.already_present)
        call = runner.calls[0]
        self.assertEqual(call.argv, ["gh", "ssh-key", "add", str(self.pub), "--type", "authentication",
                                     "--title", "github-work"])
        self.assertFalse(call.interactive)
        self.assertEqual(call.env_overrides["GH_PROMPT_DISABLED"], "1")

    def test_add_key_already_on_account(self):
        runner = FakeRunner(handler=lambda argv, _i: ok(argv, stderr="Public key already exists on your account"))
        result = sm.GitHubCLI(runner, "gh").add_key(self.pub, "github-work")
        self.assertTrue(result.success)
        self.assertTrue(result.already_present)

    def test_add_key_failures_are_not_success(self):
        for text, kind in (("HTTP 422: key is already in use", sm.GhErrorKind.DUPLICATE),
                           ("HTTP 404: needs the \"admin:public_key\" scope", sm.GhErrorKind.PERMISSION),
                           ("dial tcp: i/o timeout", sm.GhErrorKind.NETWORK)):
            with self.subTest(kind=kind):
                runner = FakeRunner(handler=lambda argv, _i, t=text: ok(argv, stderr=t, code=1))
                result = sm.GitHubCLI(runner, "gh").add_key(self.pub, "github-work")
                self.assertFalse(result.success)
                self.assertEqual(result.error_kind, kind)

    def test_add_key_refuses_non_public_key(self):
        private = self.pub.with_name("github-work")
        private.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n")
        fake_pub = self.pub.with_name("fake.pub")
        fake_pub.write_text(private.read_text())
        runner = FakeRunner()
        for path in (private, fake_pub):
            with self.subTest(path=path.name):
                with self.assertRaises(sm.ValidationError):
                    sm.GitHubCLI(runner, "gh").add_key(path, "github-work")
        self.assertEqual(runner.calls, [])

    def test_login_and_refresh_commands(self):
        runner = FakeRunner()
        gh = sm.GitHubCLI(runner, "gh")
        gh.login()
        gh.refresh_scopes()
        self.assertEqual(runner.calls[0].argv, ["gh", "auth", "login", "--hostname", "github.com",
                                                "--git-protocol", "ssh", "--web", "--skip-ssh-key"])
        self.assertTrue(runner.calls[0].interactive)
        self.assertEqual(runner.calls[1].argv, ["gh", "auth", "refresh", "--hostname", "github.com",
                                                "--scopes", "write:public_key"])

    def test_missing_gh(self):
        gh = sm.GitHubCLI(FakeRunner(), None)
        self.assertFalse(gh.available)
        with self.assertRaises(sm.CommandError) as ctx:
            gh.auth_status()
        self.assertIn("winget install --id GitHub.cli", str(ctx.exception))


class VerificationTests(unittest.TestCase):
    BODY = PUBLIC_KEY.split()[1]

    def test_verified_authentication_key(self):
        listing = f"github-work\tssh-ed25519 {self.BODY}\t2026-10-28\t1\tauthentication\n"
        self.assertEqual(sm.find_key_in_listing(listing, PUBLIC_KEY, "github-work"), sm.VerifyStatus.VERIFIED)

    def test_signing_key_is_not_confused_with_authentication_key(self):
        listing = f"github-work\tssh-ed25519 {self.BODY}\t2026-10-28\t1\tsigning\n"
        self.assertEqual(sm.find_key_in_listing(listing, PUBLIC_KEY, "github-work"), sm.VerifyStatus.SIGNING_ONLY)

    def test_title_only_and_not_found(self):
        self.assertEqual(sm.find_key_in_listing("github-work\tssh-ed25519 AAAAother\tx\t1\tauthentication",
                                                PUBLIC_KEY, "github-work"), sm.VerifyStatus.TITLE_ONLY)
        self.assertEqual(sm.find_key_in_listing("", PUBLIC_KEY, "github-work"), sm.VerifyStatus.NOT_FOUND)

    def test_verify_key_list_failure(self):
        runner = FakeRunner(handler=lambda argv, _i: ok(argv, stderr="HTTP 401: Bad credentials", code=1))
        status, message = sm.GitHubCLI(runner, "gh").verify_key(PUBLIC_KEY, "github-work")
        self.assertEqual(status, sm.VerifyStatus.ERROR)
        self.assertIn("gh auth login", message)


class GitHubConnectionTests(unittest.TestCase):
    def test_success_with_exit_code_1(self):
        result = sm.interpret_github_ssh(
            "Hi octocat! You've successfully authenticated, but GitHub does not provide shell access.", 1)
        self.assertTrue(result.success)
        self.assertEqual(result.github_identity, "octocat")
        self.assertFalse(result.deploy_key)

    def test_exit_code_alone_is_not_success(self):
        for code in (0, 1):
            with self.subTest(code=code):
                self.assertFalse(sm.interpret_github_ssh("", code).success)

    def test_permission_denied(self):
        result = sm.interpret_github_ssh("git@github.com: Permission denied (publickey).", 255)
        self.assertFalse(result.success)
        self.assertTrue(any("registrovan" in hint for hint in result.hints))

    def test_deploy_key_is_flagged(self):
        result = sm.interpret_github_ssh("Hi octo/repo! You've successfully authenticated, but ...", 1)
        self.assertTrue(result.success)
        self.assertTrue(result.deploy_key)

    def test_host_key_problems(self):
        hints = sm.ssh_failure_hints("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n"
                                     "Host key verification failed.")
        self.assertTrue(any("man-in-the-middle" in h for h in hints))
        self.assertTrue(any("Nikada ne isključujte proveru host ključa" in h for h in hints))


if __name__ == "__main__":
    unittest.main()
