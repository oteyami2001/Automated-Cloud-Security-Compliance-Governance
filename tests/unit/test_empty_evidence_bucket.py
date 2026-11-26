"""scripts/empty_evidence_bucket.py: deletes every version of exactly the project's evidence bucket (Phase 9)."""

from __future__ import annotations

import importlib.util
import sys
from typing import Any

import pytest
from conftest import ROOT

spec = importlib.util.spec_from_file_location("empty_evidence_bucket", ROOT / "scripts" / "empty_evidence_bucket.py")
assert spec and spec.loader
eb = importlib.util.module_from_spec(spec)
sys.modules["empty_evidence_bucket"] = eb
spec.loader.exec_module(eb)

ACCOUNT = "111122223333"
BUCKET = f"acscg-dev-evidence-{ACCOUNT}-us-east-2"


class FakeS3:
    def __init__(self, n: int, *, fail: int = 0, exists: bool = True) -> None:
        self.objects = [{"Key": f"evidence/k{i}.json", "VersionId": f"v{i}"} for i in range(n)]
        self.markers = [{"Key": "evidence/deleted.json", "VersionId": "m1"}]
        self.fail, self.exists = fail, exists
        self.calls: list[dict[str, Any]] = []

    def head_bucket(self, Bucket: str) -> None:  # noqa: N803 - boto3 argument name
        assert Bucket == BUCKET
        if not self.exists:
            raise RuntimeError("404")

    def list_object_versions(self, **kw: Any) -> dict[str, Any]:
        assert kw["Bucket"] == BUCKET
        everything = self.objects + self.markers
        start = int(kw.get("KeyMarker", 0))
        page = everything[start : start + 700]
        out: dict[str, Any] = {
            "Versions": [x for x in page if x["VersionId"].startswith("v")],
            "DeleteMarkers": [x for x in page if x["VersionId"].startswith("m")],
            "IsTruncated": start + 700 < len(everything),
        }
        if out["IsTruncated"]:
            out["NextKeyMarker"], out["NextVersionIdMarker"] = str(start + 700), "x"
        return out

    def delete_objects(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(kw)
        assert kw["Bucket"] == BUCKET and kw["BypassGovernanceRetention"] is True
        doomed = {(o["Key"], o["VersionId"]) for o in kw["Delete"]["Objects"]}
        failed = list(doomed)[: self.fail]
        self.fail -= len(failed)
        gone = doomed - set(failed)
        self.objects = [o for o in self.objects if (o["Key"], o["VersionId"]) not in gone]
        self.markers = [o for o in self.markers if (o["Key"], o["VersionId"]) not in gone]
        return {"Errors": [{"Key": k} for k, _ in failed]}


class FakeSts:
    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": ACCOUNT}


def run(s3: FakeS3, *args: str) -> int:
    return eb.main(["--env", "dev", "--region", "us-east-2", *args], factory=lambda _r: (s3, FakeSts()))


def test_deletes_all_versions_and_markers_in_batches(capsys: pytest.CaptureFixture[str]) -> None:
    s3 = FakeS3(2100)
    assert run(s3, "--confirm", "destroy-dev") == 0
    assert s3.objects == [] and s3.markers == []
    assert [len(c["Delete"]["Objects"]) for c in s3.calls] == [1000, 1000, 101]
    out = capsys.readouterr().out
    assert "2101 versions/markers deleted, 0 errors, 0 left" in out and ACCOUNT not in out and "evidence/k" not in out


def test_failures_and_leftovers_fail_the_run(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(FakeS3(5, fail=2), "--confirm", "destroy-dev") == 1
    assert "2 errors, 2 left" in capsys.readouterr().out


def test_refuses_without_confirmation_and_tolerates_a_missing_bucket(capsys: pytest.CaptureFixture[str]) -> None:
    s3 = FakeS3(3)
    assert run(s3, "--confirm", "yes") == 2 and s3.calls == []
    assert run(FakeS3(3, exists=False), "--confirm", "destroy-dev") == 0
    assert "nothing to empty" in capsys.readouterr().out


def test_only_project_evidence_bucket_names() -> None:
    assert eb.bucket_name("dev", ACCOUNT, "us-east-2") == BUCKET
    with pytest.raises(ValueError, match="refusing"):
        eb.bucket_name("dev", "x" * 12, "us-east-2")


def test_destroy_empties_only_after_the_digest_matched() -> None:
    script = (ROOT / "scripts" / "tf_ci.sh").read_text("utf-8")
    verify = script.index('plan_guard.py" verify')
    empty = script.index("empty_evidence_bucket.py")
    apply = script.index('terraform -chdir="$STACK" apply')
    assert verify < empty < apply
    assert 'if [ "$MODE" = destroy ]' in script[verify:empty]


def test_rebuild_script_applies_only_the_confirmed_digest() -> None:
    """scripts/rebuild.sh (CloudShell alternative): plan → typed digest confirmation → digest-checked apply."""
    import shutil
    import subprocess

    script = (ROOT / "scripts" / "rebuild.sh").read_text("utf-8")
    plan = script.index('tf_ci.sh" plan "$ENV" apply')
    confirm = script.index('[ "$ANSWER" = "${DIGEST:0:8}" ]')
    apply = script.index('EXPECTED_DIGEST=$DIGEST bash "$ROOT/scripts/tf_ci.sh" apply "$ENV" apply')
    assert plan < confirm < apply
    assert "destroy" not in script.replace("destroyed", "")  # never a destroy path
    assert "head-bucket" in script and "bootstrap.sh" in script  # stops cleanly without the bootstrap layer
    bash = shutil.which("bash") or "/bin/bash"
    subprocess.run([bash, "-n", str(ROOT / "scripts" / "rebuild.sh")], check=True)  # noqa: S603 - syntax check of this repository's script
