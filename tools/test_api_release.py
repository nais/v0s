import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("api-release-tag.sh").resolve()


class APIReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
        self.git("init", "--quiet", "-b", "main")
        self.commit("api/go.mod")

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env,
            text=True, capture_output=True, check=True,
        ).stdout.strip()

    def commit(self, path):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        with file.open("a") as out:
            out.write("change\n")
        self.git("add", path)
        self.git("commit", "--quiet", "-m", "Test change")
        return self.git("rev-parse", "HEAD")

    def release(self):
        return subprocess.run(
            ["bash", str(SCRIPT)], cwd=self.repo, env=self.env,
            text=True, capture_output=True,
        )

    def assert_tag(self, expected):
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), expected)

    def test_bootstrap_continues_previous_repository_versions(self):
        self.assert_tag("api/v0.3.0")

    def test_rerun_at_release_commit_does_not_release(self):
        self.git("tag", "-a", "api/v0.3.0", "-m", "API release")
        self.assert_tag("")

    def test_server_only_change_does_not_release(self):
        self.git("tag", "api/v0.3.0")
        self.commit("internal/server.go")
        self.assert_tag("")

    def test_client_or_contract_change_increments_minor(self):
        self.git("tag", "api/v0.3.0")
        for path in ("api/go.mod", "proto/v0s/v1/v0s.proto"):
            with self.subTest(path=path):
                self.commit(path)
                self.assert_tag("api/v0.4.0")
                self.git("tag", "-f", "api/v0.3.0")

    def test_uses_latest_semantic_version_and_resets_patch(self):
        self.git("tag", "api/v0.9.0")
        self.git("tag", "api/v0.10.2")
        self.commit("api/client.go")
        self.assert_tag("api/v0.11.0")

    def test_failed_release_is_recovered_by_next_server_push(self):
        self.git("tag", "api/v0.3.0")
        self.commit("api/client.go")
        self.commit("internal/server.go")
        self.assert_tag("api/v0.4.0")

    def test_older_workflow_does_not_release_after_newer_one(self):
        older = self.git("rev-parse", "HEAD")
        self.commit("api/client.go")
        self.git("tag", "api/v0.4.0")
        self.git("checkout", "--quiet", "--detach", older)
        self.assert_tag("")

    def test_divergent_release_fails(self):
        base = self.git("rev-parse", "HEAD")
        self.commit("api/client.go")
        self.git("tag", "api/v0.4.0")
        self.git("checkout", "--quiet", "--detach", base)
        self.commit("api/other.go")
        result = self.release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not on the current history", result.stderr)

    def test_unsupported_version_fails(self):
        self.git("tag", "api/v1.0.0")
        result = self.release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported API release tag", result.stderr)


if __name__ == "__main__":
    unittest.main()
