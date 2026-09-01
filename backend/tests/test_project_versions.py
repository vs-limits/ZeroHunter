from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import sys


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.server import import_jobs, observability, paths, projects, scans


class ProjectVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.tmp.name) / "repo"
        self.repo_root.mkdir()
        self.orig_paths_repo = paths.REPO_ROOT
        self.orig_projects_repo = projects.REPO_ROOT
        self.orig_observability_repo = observability.REPO_ROOT
        paths.REPO_ROOT = self.repo_root
        projects.REPO_ROOT = self.repo_root
        observability.REPO_ROOT = self.repo_root

    def tearDown(self) -> None:
        paths.REPO_ROOT = self.orig_paths_repo
        projects.REPO_ROOT = self.orig_projects_repo
        observability.REPO_ROOT = self.orig_observability_repo
        self.tmp.cleanup()

    def test_project_path_requires_version(self) -> None:
        projects.create_version(
            "dataset",
            "defectmine",
            "case",
            kind="manual",
            version="default__manual",
        )
        with self.assertRaises(ValueError):
            paths.project_dir("dataset/defectmine/case")
        self.assertTrue(paths.project_dir("dataset/defectmine/case/default__manual").is_dir())

    def test_project_extra_fields_are_optional_and_persisted(self) -> None:
        project = projects.create_project(
            source="dataset",
            owner="defectmine",
            repo="case",
        )
        self.assertEqual(project["description"], "")
        self.assertEqual(project["tags"], [])
        self.assertEqual(project["audit_status"], "not_started")
        self.assertFalse(project["favorite"])
        self.assertEqual(project["project_profile"], {})

        updated = projects.update_project(
            "dataset",
            "defectmine",
            "case",
            description="审计样本",
            tags=["Java", "Java", "CMS"],
            audit_status="tracking",
            favorite=True,
            project_profile={
                "project_name": "ignored",
                "summary": "画像",
                "confidence": {"overall": "high"},
                "limits": ["ignored"],
            },
        )
        self.assertEqual(updated["description"], "审计样本")
        self.assertEqual(updated["tags"], ["Java", "CMS"])
        self.assertEqual(updated["audit_status"], "tracking")
        self.assertTrue(updated["favorite"])
        self.assertEqual(updated["project_profile"], {"summary": "画像"})

    def test_manual_version_create_rejects_and_overwrites(self) -> None:
        first = projects.create_version(
            "dataset",
            "defectmine",
            "case",
            kind="manual",
            version="default__manual",
        )
        self.assertEqual(first["project_path"], "dataset/defectmine/case/default__manual")
        with self.assertRaises(FileExistsError):
            projects.create_version(
                "dataset",
                "defectmine",
                "case",
                kind="manual",
                version="default__manual",
            )
        second = projects.create_version(
            "dataset",
            "defectmine",
            "case",
            kind="manual",
            version="default__manual",
            overwrite=True,
        )
        self.assertEqual(second["version"], "default__manual")

    def test_scan_lands_under_version_artifacts(self) -> None:
        projects.create_version("dataset", "defectmine", "case", kind="manual", version="vuln__v1")
        meta = scans.create_scan(
            "dataset/defectmine/case/vuln__v1",
            name="unit",
            agents=["treescan"],
        )
        scan_json = (
            self.repo_root
            / "dataset"
            / "defectmine"
            / "case"
            / "vuln__v1"
            / ".defectmine"
            / "scans"
            / meta["scan_id"]
            / "scan.json"
        )
        self.assertTrue(scan_json.is_file())
        self.assertEqual(scans.list_all_scans()[0]["project_path"], "dataset/defectmine/case/vuln__v1")

    def test_dashboard_fingerprint_changes_when_verification_changes(self) -> None:
        projects.create_version("dataset", "defectmine", "case", kind="manual", version="vuln__v1")
        meta = scans.create_scan(
            "dataset/defectmine/case/vuln__v1",
            name="unit",
            agents=["auditor"],
        )

        before = observability._scan_repo_fingerprint()
        scan_dir = (
            self.repo_root
            / "dataset"
            / "defectmine"
            / "case"
            / "vuln__v1"
            / ".defectmine"
            / "scans"
            / meta["scan_id"]
        )
        time.sleep(0.01)
        (scan_dir / "verification.json").write_text(
            '{"C-test":{"人工核验":"false_positive","人工-Review":"unit"}}\n',
            encoding="utf-8",
        )

        after = observability._scan_repo_fingerprint()

        self.assertEqual(before[0], after[0])
        self.assertNotEqual(before, after)

    def test_git_import_uses_mirror_and_worktree(self) -> None:
        origin = Path(self.tmp.name) / "origin"
        origin.mkdir()
        subprocess.run(["git", "init"], cwd=origin, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.email", "unit@example.test"], cwd=origin, check=True)
        subprocess.run(["git", "config", "user.name", "Unit Test"], cwd=origin, check=True)
        (origin / "README.md").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=origin, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=origin, check=True, stdout=subprocess.DEVNULL)

        job = import_jobs.start_git_import(
            "github",
            "unit",
            "sample",
            {"git_url": str(origin), "ref": "HEAD", "version": "main__unit"},
        )
        final = self._wait_job(job["job_id"])
        self.assertEqual(final["status"], "done", final.get("lines"))
        target = self.repo_root / "github" / "unit" / "sample" / "main__unit"
        self.assertTrue((target / "README.md").is_file())
        self.assertTrue((target / ".git").is_file())
        self.assertTrue(
            (self.repo_root / "github" / "unit" / "sample" / ".defectmine_repo" / "git" / "mirror.git").is_dir()
        )
        refs = import_jobs.list_git_refs("github", "unit", "sample")
        self.assertEqual(refs["source"], "mirror")
        self.assertTrue(any(item["kind"] == "branch" for item in refs["items"]))

    def test_git_refs_list_remote_before_import(self) -> None:
        origin = Path(self.tmp.name) / "origin-refs"
        origin.mkdir()
        subprocess.run(["git", "init"], cwd=origin, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "config", "user.email", "unit@example.test"], cwd=origin, check=True)
        subprocess.run(["git", "config", "user.name", "Unit Test"], cwd=origin, check=True)
        (origin / "README.md").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=origin, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=origin, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "branch", "-M", "main"], cwd=origin, check=True)
        subprocess.run(["git", "branch", "release/old"], cwd=origin, check=True)
        subprocess.run(["git", "tag", "v1.0.0"], cwd=origin, check=True)

        refs = import_jobs.list_git_refs(
            "github",
            "unit",
            "sample",
            git_url=str(origin),
        )

        names = {(item["kind"], item["name"]) for item in refs["items"]}
        self.assertIn(("branch", "main"), names)
        self.assertIn(("branch", "release/old"), names)
        self.assertIn(("tag", "v1.0.0"), names)
        self.assertTrue(all(len(item["short_commit"]) == 12 for item in refs["items"]))

    def _wait_job(self, job_id: str) -> dict:
        deadline = time.time() + 20
        while time.time() < deadline:
            job = import_jobs.get_job(job_id)
            if job and job["status"] in {"done", "error", "killed"}:
                return job
            time.sleep(0.1)
        self.fail(f"job did not finish: {job_id}")


if __name__ == "__main__":
    unittest.main()
