import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import FakeRunner, ok, sm

GITHUB_SPEC = sm.HostSpec("github-work", sm.HostKind.GITHUB, "github.com", "git", "~/.ssh/github-work")
SERVER_SPEC = sm.HostSpec("prod", sm.HostKind.SERVER, "203.0.113.10", "deploy", "~/.ssh/prod", port=2222)

EXISTING = """# Personal settings
Include config.d/*

# Work laptop
Host work-box
    HostName 10.0.0.5
    User alice

Host *.internal !bastion.internal
    ProxyJump bastion

Host *
    ServerAliveInterval 30
"""


def lines_preserved(original: str, updated: str) -> bool:
    """Every original line appears in the updated text, in order."""
    remaining = iter(updated.splitlines(keepends=True))
    return all(any(line == candidate for candidate in remaining) for line in original.splitlines(keepends=True))


class ParsingTests(unittest.TestCase):
    def test_split_config_args(self):
        self.assertEqual(sm.split_config_args('a b  "c d" e'), ["a", "b", "c d", "e"])
        self.assertEqual(sm.split_config_args("a # comment"), ["a"])
        self.assertEqual(sm.split_config_args('"#notcomment" x'), ["#notcomment", "x"])

    def test_host_pattern_matches(self):
        self.assertTrue(sm.host_pattern_matches("github-*", "GitHub-Work"))
        self.assertTrue(sm.host_pattern_matches("prod?", "prod1"))
        self.assertFalse(sm.host_pattern_matches("prod?", "prod12"))
        self.assertFalse(sm.host_pattern_matches("a.b", "axb"))

    def test_parses_managed_blocks_and_options(self):
        doc = sm.SSHConfigDocument(EXISTING).with_block_added(SERVER_SPEC, "2026-10-28")
        blocks = doc.managed_blocks()
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].alias, "prod")
        self.assertEqual(blocks[0].kind, "server")
        self.assertEqual(blocks[0].options["hostname"], "203.0.113.10")
        self.assertEqual(blocks[0].options["port"], "2222")
        self.assertEqual(blocks[0].options["identityfile"], "~/.ssh/prod")

    def test_unmanaged_aliases(self):
        doc = sm.SSHConfigDocument(EXISTING)
        self.assertEqual(doc.unmanaged_aliases(), ["work-box", "*.internal", "!bastion.internal", "*"])

    def test_malformed_markers_raise(self):
        cases = {
            "missing end": "# BEGIN SSH-MANAGER a kind=server\nHost a\n",
            "orphan end": "Host x\n# END SSH-MANAGER a\n",
            "nested": "# BEGIN SSH-MANAGER a kind=server\n# BEGIN SSH-MANAGER b kind=server\n",
            "mismatched": "# BEGIN SSH-MANAGER a kind=server\n# END SSH-MANAGER b\n",
        }
        for label, text in cases.items():
            with self.subTest(label):
                with self.assertRaises(sm.ConfigError):
                    sm.SSHConfigDocument(text)


class DuplicateDetectionTests(unittest.TestCase):
    def test_unmanaged_duplicate_is_reported_case_insensitively(self):
        conflicts = sm.SSHConfigDocument(EXISTING).find_alias_conflicts("WORK-BOX")
        self.assertEqual(conflicts.unmanaged_lines, [5])
        self.assertIsNone(conflicts.managed)

    def test_duplicate_in_multi_pattern_host_line(self):
        conflicts = sm.SSHConfigDocument("Host one two github-work\n  User x\n").find_alias_conflicts("github-work")
        self.assertEqual(conflicts.unmanaged_lines, [1])

    def test_managed_duplicate_is_reported(self):
        doc = sm.SSHConfigDocument(EXISTING).with_block_added(GITHUB_SPEC, "d")
        conflicts = doc.find_alias_conflicts("github-work")
        self.assertIsNotNone(conflicts.managed)
        self.assertEqual(conflicts.unmanaged_lines, [])

    def test_wildcards_are_reported_but_star_and_negations_are_ignored(self):
        doc = sm.SSHConfigDocument(EXISTING + "Host github-*\n  User y\n")
        conflicts = doc.find_alias_conflicts("github-work")
        self.assertEqual(conflicts.wildcard_patterns, ["github-*"])
        self.assertEqual(sm.SSHConfigDocument(EXISTING).find_alias_conflicts("bastion.internal").unmanaged_lines, [])
        self.assertEqual(sm.SSHConfigDocument(EXISTING).find_alias_conflicts("db.internal").wildcard_patterns,
                         ["*.internal"])

    def test_no_conflict_for_new_alias(self):
        conflicts = sm.SSHConfigDocument(EXISTING).find_alias_conflicts("github-personal")
        self.assertIsNone(conflicts.managed)
        self.assertEqual(conflicts.unmanaged_lines, [])
        self.assertEqual(conflicts.wildcard_patterns, [])

    def test_adding_twice_is_refused(self):
        doc = sm.SSHConfigDocument("").with_block_added(GITHUB_SPEC, "d")
        with self.assertRaises(sm.ConfigError):
            doc.with_block_added(GITHUB_SPEC, "d")


class UpdateTests(unittest.TestCase):
    def test_block_contents_for_github(self):
        text = sm.SSHConfigDocument("").with_block_added(GITHUB_SPEC, "2026-10-28").text
        self.assertIn("# BEGIN SSH-MANAGER github-work kind=github\n", text)
        self.assertIn("# END SSH-MANAGER github-work\n", text)
        for expected in ("Host github-work\n", "    HostName github.com\n", "    User git\n",
                         "    IdentityFile ~/.ssh/github-work\n", "    IdentitiesOnly yes\n",
                         "    AddKeysToAgent yes\n"):
            self.assertIn(expected, text)
        self.assertNotIn("Port", text)
        self.assertNotIn("github-github", text)
        self.assertNotIn("StrictHostKeyChecking", text)

    def test_server_block_includes_port(self):
        text = sm.SSHConfigDocument("").with_block_added(SERVER_SPEC, "d").text
        self.assertIn("    Port 2222\n", text)
        self.assertIn("    User deploy\n", text)

    def test_existing_content_is_preserved_and_block_precedes_first_host(self):
        updated = sm.SSHConfigDocument(EXISTING).with_block_added(GITHUB_SPEC, "d").text
        self.assertTrue(lines_preserved(EXISTING, updated))
        self.assertLess(updated.index("Host github-work"), updated.index("Host work-box"))
        self.assertLess(updated.index("Include config.d/*"), updated.index("# BEGIN SSH-MANAGER"))
        # The comment describing "work-box" stays attached to it.
        self.assertLess(updated.index("# END SSH-MANAGER"), updated.index("# Work laptop"))
        self.assertIn("# Work laptop\nHost work-box", updated)

    def test_global_only_config_gets_block_appended(self):
        original = "ServerAliveInterval 60"  # no trailing newline
        updated = sm.SSHConfigDocument(original).with_block_added(GITHUB_SPEC, "d").text
        self.assertTrue(updated.startswith("ServerAliveInterval 60\n\n# BEGIN SSH-MANAGER github-work"))

    def test_crlf_and_bom_are_preserved(self):
        original = EXISTING.replace("\n", "\r\n").encode("utf-8")
        doc = sm.SSHConfigDocument.from_bytes(b"\xef\xbb\xbf" + original)
        data = doc.with_block_added(GITHUB_SPEC, "d").to_bytes()
        self.assertTrue(data.startswith(b"\xef\xbb\xbf"))
        text = data[3:].decode("utf-8")
        self.assertNotIn("\n", text.replace("\r\n", ""))
        self.assertIn("Host github-work\r\n", text)

    def test_non_utf8_config_is_refused(self):
        with self.assertRaises(sm.ConfigError):
            sm.SSHConfigDocument.from_bytes(b"Host caf\xe9\n")

    def test_replace_only_changes_managed_block(self):
        doc = sm.SSHConfigDocument(EXISTING).with_block_added(SERVER_SPEC, "d")
        new_spec = sm.HostSpec("prod", sm.HostKind.SERVER, "198.51.100.7", "ops", "~/.ssh/prod")
        replaced = doc.with_block_replaced(new_spec, "d2").text
        self.assertTrue(lines_preserved(EXISTING, replaced))
        self.assertIn("HostName 198.51.100.7", replaced)
        self.assertNotIn("203.0.113.10", replaced)
        self.assertEqual(len(sm.SSHConfigDocument(replaced).managed_blocks()), 1)

    def test_replace_missing_block_raises(self):
        with self.assertRaises(sm.ConfigError):
            sm.SSHConfigDocument(EXISTING).with_block_replaced(GITHUB_SPEC, "d")

    def test_identity_file_for(self):
        home = Path("/home/u") if Path("/").anchor == "/" else Path("C:/Users/u")
        self.assertEqual(sm.identity_file_for(home / ".ssh" / "k", home), "~/.ssh/k")
        self.assertEqual(sm.identity_file_for(Path("/other dir/k").resolve(), home)[0], '"')


class ConfigManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.path = self.home / ".ssh" / "config"
        self.resolve_output = ("hostname github.com\nuser git\nport 22\nidentitiesonly yes\n"
                               "identityfile ~/.ssh/github-work\n")
        self.ssh_g_code = 0
        self.runner = FakeRunner(handler=lambda argv, _i: ok(argv, self.resolve_output, "bad option", self.ssh_g_code))
        self.manager = sm.SSHConfigManager(self.path, self.runner, "ssh", self.home, is_default_path=False)

    def test_missing_config_is_created(self):
        result = self.manager.apply(GITHUB_SPEC)
        self.assertTrue(result.created)
        self.assertIsNone(result.backup)
        self.assertTrue(result.validated)
        self.assertEqual(result.warnings, [])
        self.assertIn("Host github-work", self.path.read_text())
        self.assertEqual(self.runner.calls[-1].argv, ["ssh", "-G", "-F", str(self.path), "github-work"])

    def test_existing_config_is_backed_up_and_preserved(self):
        self.path.parent.mkdir()
        self.path.write_text(EXISTING)
        result = self.manager.apply(GITHUB_SPEC)
        self.assertFalse(result.created)
        self.assertEqual(result.backup.read_text(), EXISTING)
        self.assertTrue(lines_preserved(EXISTING, self.path.read_text()))

    def test_backups_are_never_overwritten(self):
        self.path.parent.mkdir()
        self.path.write_text("one\n")
        first = sm.create_backup(self.path)
        second = sm.create_backup(self.path)
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists() and second.exists())

    def test_failed_write_preserves_original(self):
        self.path.parent.mkdir()
        self.path.write_text(EXISTING)
        with mock.patch.object(sm.os, "replace", side_effect=PermissionError("locked")):
            with self.assertRaises(sm.ConfigError) as ctx:
                self.manager.apply(GITHUB_SPEC)
        self.assertIn("Originalni config nije promenjen", str(ctx.exception))
        self.assertEqual(self.path.read_text(), EXISTING)
        self.assertEqual([p.name for p in self.path.parent.iterdir() if p.suffix == ".tmp"], [])

    def test_invalid_result_is_rolled_back(self):
        self.path.parent.mkdir()
        self.path.write_text(EXISTING)
        self.ssh_g_code = 255
        with self.assertRaises(sm.ConfigError) as ctx:
            self.manager.apply(GITHUB_SPEC)
        self.assertIn("originalni sadržaj vraćen", str(ctx.exception))
        self.assertEqual(self.path.read_text(), EXISTING)

    def test_mismatch_from_earlier_global_options_is_reported(self):
        self.resolve_output = self.resolve_output.replace("user git", "user someone-else")
        result = self.manager.apply(GITHUB_SPEC)
        self.assertTrue(any("Efektivni User je 'someone-else'" in w for w in result.warnings))

    def test_without_ssh_validation_is_skipped_with_warning(self):
        manager = sm.SSHConfigManager(self.path, self.runner, None, self.home)
        result = manager.apply(GITHUB_SPEC)
        self.assertFalse(result.validated)
        self.assertTrue(result.warnings)

    def test_load_rejects_directory(self):
        self.path.mkdir(parents=True)
        with self.assertRaises(sm.ConfigError):
            self.manager.load()

    def test_compare_resolved_accepts_expanded_identity(self):
        options = sm.parse_ssh_g_output(
            f"hostname GitHub.com\nuser git\nport 22\nidentitiesonly yes\n"
            f"identityfile {self.home / '.ssh' / 'github-work'}\n"
        )
        self.assertEqual(sm.compare_resolved(GITHUB_SPEC, options, self.home), [])


if __name__ == "__main__":
    unittest.main()
