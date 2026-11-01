import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sync_upstream as updater


RULES = [{"type": "pull_request"}, {"type": "required_status_checks", "parameters": {
    "strict_required_status_checks_policy": True,
    "required_status_checks": [{"context": c} for c in updater.REQUIRED]}}]


class SyncTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.old = Path.cwd()
        self.addCleanup(os.chdir, self.old)
        root = Path(self.folder.name)
        self.origin, self.work, self.upstream = root / "origin", root / "work", root / "upstream"
        self.run_git("init", "--bare", str(self.origin))
        self.run_git("-C", str(self.origin), "symbolic-ref", "HEAD", "refs/heads/main")
        self.run_git("init", "-b", "main", str(self.work))
        os.chdir(self.work)
        self.identity()
        Path("shared.txt").write_text("base\n")
        self.commit("Initial base")
        self.run_git("remote", "add", "origin", str(self.origin))
        self.run_git("push", "origin", "main")
        self.run_git("clone", str(self.origin), str(self.upstream))
        self.run_git("-C", str(self.upstream), "config", "user.name", "Test")
        self.run_git("-C", str(self.upstream), "config", "user.email", "test@example.invalid")
        Path("fork.txt").write_text("Keep fork code\n")
        self.commit("Add fork code")
        self.run_git("push", "origin", "main")
        self.initial = self.run_git("rev-parse", "HEAD").stdout.strip()
        self.calls = []

    def run_git(self, *args):
        return subprocess.run(["git", *args], check=True, capture_output=True, text=True)

    def identity(self):
        self.run_git("config", "user.name", "Test")
        self.run_git("config", "user.email", "test@example.invalid")

    def commit(self, message):
        self.run_git("add", ".")
        self.run_git("commit", "-m", message)

    def release(self, conflict=False, changed=True):
        if conflict:
            Path("shared.txt").write_text("fork\n")
            self.commit("Change fork side")
            self.run_git("push", "origin", "main")
            self.initial = self.run_git("rev-parse", "HEAD").stdout.strip()
        if changed:
            (self.upstream / ("shared.txt" if conflict else "upstream.txt")).write_text("upstream\n")
            self.run_git("-C", str(self.upstream), "add", ".")
            self.run_git("-C", str(self.upstream), "commit", "-m", "Upstream change")
        self.run_git("-C", str(self.upstream), "tag", "v1")

    def execute(self, rules=RULES, tag="v1", pending=None):
        original = updater.command

        def fake(*args, check=True):
            if args[0] == "git":
                if args[1] == "fetch":
                    args = (*args[:3], str(self.upstream), *args[4:])
                return original(*args, check=check)
            self.calls.append(args)
            if args[0] == "go" and args[1:3] == ("run", "./infra/vprotogen/main.go"):
                target = Path("app/policy/command/command.pb.go")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("// regenerated fixture\n")
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[1:3] == ("pr", "list"):
                output = json.dumps(pending or [])
            elif args[1:3] == ("pr", "create"):
                output = "https://github.com/example/fork/pull/1"
            elif args[1:3] == ("pr", "view"):
                output = '{"id":"PR_test"}'
            elif args[1] == "api" and args[2].endswith("releases/latest"):
                output = json.dumps({"tag_name": tag})
            elif args[1] == "api" and "rules/branches" in args[2]:
                output = json.dumps(rules)
            elif args[1:3] == ("api", "graphql"):
                output = '{}'
            else:
                raise AssertionError(args)
            return subprocess.CompletedProcess(args, 0, output, "")

        with patch.object(updater, "command", side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
            updater.sync("example/fork")
        self.assertEqual(self.run_git("rev-parse", "main").stdout.strip(), self.initial)
        self.assertEqual(self.run_git("--git-dir", str(self.origin), "rev-parse", "main").stdout.strip(), self.initial)

    def test_clean_merge_preserves_fork_and_enables_guarded_auto_merge(self):
        self.release()
        self.execute()
        self.assertTrue(Path("fork.txt").exists())
        self.assertTrue(Path("upstream.txt").exists())
        self.assertTrue(any(c[0:3] == ("go", "run", "./infra/vprotogen/main.go") for c in self.calls))
        self.assertEqual(self.run_git("show", "HEAD:app/policy/command/command.pb.go").stdout,
                         "// regenerated fixture\n")
        self.assertTrue(any(c[1:3] == ("api", "graphql") for c in self.calls))

    def test_conflict_creates_only_a_draft_record(self):
        self.release(conflict=True)
        self.execute()
        self.assertEqual(Path("shared.txt").read_text(), "fork\n")
        record = json.loads(Path(".github/upstream-conflict.json").read_text())
        self.assertIn("shared.txt", record["conflicts"])
        self.assertTrue(any("--draft" in c for c in self.calls))
        self.assertFalse(any(c[1:3] == ("api", "graphql") for c in self.calls))
        self.assertFalse(any(c[0] == "go" for c in self.calls))

    def test_missing_rules_never_enable_auto_merge(self):
        self.release()
        self.execute(rules=[])
        self.assertTrue(any(c[1:3] == ("pr", "create") for c in self.calls))
        self.assertFalse(any(c[1:3] == ("api", "graphql") for c in self.calls))

    def test_old_three_check_ruleset_does_not_enable_auto_merge(self):
        self.release()
        old_checks = {f"local-regression ({system}-latest)" for system in ("ubuntu", "windows", "macos")}
        rules = [{"type": "pull_request"}, {"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [{"context": check} for check in old_checks],
        }}]
        self.execute(rules=rules)
        self.assertFalse(any(c[1:3] == ("api", "graphql") for c in self.calls))

    def test_missing_windows_core_test_prevents_auto_merge(self):
        self.release()
        rules = [{"type": "pull_request"}, {"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [
                {"context": check} for check in updater.REQUIRED if check != "test (windows-latest)"
            ],
        }}]
        self.execute(rules=rules)
        self.assertFalse(any(c[1:3] == ("api", "graphql") for c in self.calls))

    def test_already_included_release_does_not_create_pr(self):
        self.release(changed=False)
        self.execute()
        self.assertFalse(any(c[0] == "go" for c in self.calls))
        self.assertFalse(any(c[1:3] == ("pr", "create") for c in self.calls))

    def test_open_update_is_not_overwritten(self):
        self.execute(pending=[{"headRefName": "updates/xray-existing", "url": "test"}])
        self.assertFalse(any(c[1:3] == ("pr", "create") for c in self.calls))

    def test_invalid_tag_is_rejected(self):
        with self.assertRaises(ValueError):
            self.execute(tag="../../bad")


if __name__ == "__main__":
    unittest.main()
