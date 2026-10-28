import unittest

from tests.helpers import sm


class KeyNameValidationTests(unittest.TestCase):
    def test_accepts_typical_names(self):
        for name in ("github-work", "github-personal", "production-server", "db_01", "prod.server", "A1"):
            with self.subTest(name=name):
                self.assertEqual(sm.validate_key_name(name), name)

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(sm.validate_key_name("  github-work \n"), "github-work")

    def test_rejects_path_traversal_and_separators(self):
        for name in ("../evil", "..\\evil", "a/b", "a\\b", "C:evil", "a..b", "..", "."):
            with self.subTest(name=name):
                with self.assertRaises(sm.ValidationError):
                    sm.validate_key_name(name)

    def test_rejects_invalid_characters(self):
        for name in ("", "   ", "with space", "-leading-dash", ".hidden", "_x", "star*", "q?", "semi;colon",
                     "quote\"", "amp&", "pipe|", "dollar$", "percent%", "unicodé", "tab\tname"):
            with self.subTest(name=name):
                with self.assertRaises(sm.ValidationError):
                    sm.validate_key_name(name)

    def test_rejects_reserved_names(self):
        for name in ("con", "NUL", "com1", "lpt9.txt", "config", "known_hosts", "authorized_keys",
                     "id_ed25519", "id_rsa", "github.com", "SSH.GitHub.com", "key.pub", "trailing."):
            with self.subTest(name=name):
                with self.assertRaises(sm.ValidationError):
                    sm.validate_key_name(name)

    def test_length_limit(self):
        self.assertEqual(sm.validate_key_name("a" * 64), "a" * 64)
        with self.assertRaises(sm.ValidationError):
            sm.validate_key_name("a" * 65)


class AliasTests(unittest.TestCase):
    def test_github_suggestion_never_doubles_prefix(self):
        self.assertEqual(sm.suggest_github_name("github-work"), "github-work")
        self.assertEqual(sm.suggest_github_name("GitHub-Work"), "GitHub-Work")
        self.assertEqual(sm.suggest_github_name("githubwork"), "githubwork")
        self.assertEqual(sm.suggest_github_name("work"), "github-work")

    def test_remote_url_uses_exact_alias(self):
        self.assertEqual(sm.github_remote_url("github-work", "OWNER", "REPOSITORY"),
                         "git@github-work:OWNER/REPOSITORY.git")
        self.assertEqual(sm.github_remote_url("github-work", "octo", "repo.git"), "git@github-work:octo/repo.git")
        self.assertNotIn("github-github", sm.github_remote_url(sm.suggest_github_name("github-work"), "o", "r"))

    def test_remote_url_rejects_bad_alias(self):
        for alias in ("", "bad alias", "-oProxyCommand=x", "a*"):
            with self.subTest(alias=alias):
                with self.assertRaises(sm.ValidationError):
                    sm.github_remote_url(alias, "o", "r")

    def test_parse_owner_repo(self):
        self.assertEqual(sm.parse_owner_repo("octo/hello-world"), ("octo", "hello-world"))
        self.assertEqual(sm.parse_owner_repo("octo/hello.git"), ("octo", "hello"))
        for raw in ("octo", "a/b/c", "-bad/repo", "octo/..", "octo/re po", "/repo"):
            with self.subTest(raw=raw):
                with self.assertRaises(sm.ValidationError):
                    sm.parse_owner_repo(raw)

    def test_alias_token(self):
        self.assertEqual(sm.validate_alias_token(" prod "), "prod")
        for raw in ("-oProxyCommand=calc", "a b", "x*", "", "a..b"):
            with self.subTest(raw=raw):
                with self.assertRaises(sm.ValidationError):
                    sm.validate_alias_token(raw)


class HostUserPortValidationTests(unittest.TestCase):
    def test_hostnames(self):
        self.assertEqual(sm.validate_hostname("server.example.com"), "server.example.com")
        self.assertEqual(sm.validate_hostname("203.0.113.10"), "203.0.113.10")
        self.assertEqual(sm.validate_hostname("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(sm.validate_hostname("my_host"), "my_host")
        for raw in ("", "-oProxyCommand=x", "bad host", "host;rm", "fe80::1%eth0", "a" * 64 + ".com",
                    "x..y", "%h", "host/path"):
            with self.subTest(raw=raw):
                with self.assertRaises(sm.ValidationError):
                    sm.validate_hostname(raw)

    def test_usernames(self):
        for raw in ("deploy", "root", "user.name", "first-last", "user@domain.local"):
            with self.subTest(raw=raw):
                self.assertEqual(sm.validate_username(raw), raw)
        for raw in ("", "-oX", "two words", "a" * 65, "%u", "bad;user"):
            with self.subTest(raw=raw):
                with self.assertRaises(sm.ValidationError):
                    sm.validate_username(raw)

    def test_ports(self):
        self.assertIsNone(sm.validate_port(""))
        self.assertEqual(sm.validate_port("22"), 22)
        self.assertEqual(sm.validate_port("65535"), 65535)
        for raw in ("0", "65536", "-1", "abc", "22.5"):
            with self.subTest(raw=raw):
                with self.assertRaises(sm.ValidationError):
                    sm.validate_port(raw)


class RedactionTests(unittest.TestCase):
    def test_redacts_tokens_and_private_keys(self):
        text = ("token gho_abcdefghijklmnopqrstuvwxyz123456 and github_pat_11ABCDEFG0123456789_abcdefghij\n"
                "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
        cleaned = sm.redact(text)
        self.assertNotIn("gho_abc", cleaned)
        self.assertNotIn("github_pat_11", cleaned)
        self.assertNotIn("AAAA", cleaned)
        self.assertIn("[UKLONJENO]", cleaned)

    def test_excerpt_limits_lines(self):
        self.assertEqual(sm.excerpt("\n".join(str(i) for i in range(20)), max_lines=3), "0\n1\n2\n...")


if __name__ == "__main__":
    unittest.main()
