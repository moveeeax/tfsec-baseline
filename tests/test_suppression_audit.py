import datetime as dt
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools import suppression_audit as sa  # noqa: E402

TODAY = dt.date(2026, 8, 19)


def _sup(**over):
    base = dict(
        id="CKV_AWS_18",
        paths=["modules/s3"],
        justification="access logging handled centrally by the platform team",
        owner="platform-team",
        expires="2026-12-31",
    )
    base.update(over)
    return base


def test_parse_accepts_top_level_list():
    rows = sa.parse_suppressions([_sup(), _sup(id="CKV_AWS_21")])
    assert [r.check_id for r in rows] == ["CKV_AWS_18", "CKV_AWS_21"]


def test_parse_accepts_mapping_with_key():
    rows = sa.parse_suppressions({"suppressions": [_sup()]})
    assert len(rows) == 1
    assert rows[0].paths == ["modules/s3"]


def test_parse_coerces_scalar_path_to_list():
    rows = sa.parse_suppressions([_sup(paths="modules/s3/main.tf")])
    assert rows[0].paths == ["modules/s3/main.tf"]


def test_parse_rejects_non_list():
    with pytest.raises(ValueError):
        sa.parse_suppressions(42)


def test_valid_waiver_is_active_and_clean():
    res = sa.validate(sa.parse_suppressions([_sup()]), TODAY)
    assert res.ok
    assert len(res.active) == 1
    assert res.errors == []


def test_expired_waiver_is_error():
    res = sa.validate(sa.parse_suppressions([_sup(expires="2026-01-01")]), TODAY)
    assert not res.ok
    assert any("expired" in p.message for p in res.errors)
    assert res.active == []


def test_short_justification_is_error():
    res = sa.validate(sa.parse_suppressions([_sup(justification="wip")]), TODAY)
    assert any("justification" in p.message for p in res.errors)


def test_missing_owner_is_error():
    res = sa.validate(sa.parse_suppressions([_sup(owner="")]), TODAY)
    assert any("owner" in p.message for p in res.errors)


def test_bad_check_id_is_error():
    res = sa.validate(sa.parse_suppressions([_sup(id="totally-made-up")]), TODAY)
    assert any("check id" in p.message for p in res.errors)


def test_missing_paths_is_error():
    res = sa.validate(sa.parse_suppressions([_sup(paths=[])]), TODAY)
    assert any("paths" in p.message for p in res.errors)


def test_bad_date_format_is_error():
    res = sa.validate(sa.parse_suppressions([_sup(expires="31-12-2026")]), TODAY)
    assert any("ISO date" in p.message for p in res.errors)


def test_expiring_soon_is_warning_not_error():
    res = sa.validate(sa.parse_suppressions([_sup(expires="2026-09-01")]), TODAY)
    assert res.ok  # warnings don't fail the build
    assert len(res.warnings) == 1
    assert len(res.active) == 1


def test_broken_row_is_not_counted_active():
    res = sa.validate(sa.parse_suppressions([_sup(owner="")]), TODAY)
    assert res.active == []


def test_emit_checkov_skips_dedupes_active_only():
    rows = sa.parse_suppressions(
        [_sup(id="CKV_AWS_18"), _sup(id="CKV_AWS_18"), _sup(id="CKV_AWS_21"),
         _sup(id="CKV_AWS_99", expires="2026-01-01")]
    )
    res = sa.validate(rows, TODAY)
    skips = sa.emit_checkov_skips(res)
    assert skips == "CKV_AWS_18,CKV_AWS_21"  # deduped, expired one excluded


def test_sarif_shape_is_valid():
    res = sa.validate(sa.parse_suppressions([_sup(expires="2026-01-01")]), TODAY)
    doc = sa.to_sarif(res, "supp.yaml")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "suppression-audit"
    assert run["results"][0]["level"] == "error"
    json.dumps(doc)  # must be serialisable


def test_main_clean_file_exit_zero(tmp_path, capsys):
    import yaml
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump([_sup()]))
    code = sa.main(["--file", str(p), "--today", "2026-08-19"])
    assert code == 0
    assert "OK:" in capsys.readouterr().out


def test_main_expired_file_exit_one(tmp_path):
    import yaml
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump([_sup(expires="2020-01-01")]))
    assert sa.main(["--file", str(p), "--today", "2026-08-19"]) == 1


def test_main_missing_file_exit_two():
    assert sa.main(["--file", "/nope/does-not-exist.yaml"]) == 2


def test_main_bad_today_exit_two(tmp_path):
    import yaml
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump([_sup()]))
    assert sa.main(["--file", str(p), "--today", "not-a-date"]) == 2


# --- inline skips (--scan-inline) -------------------------------------------

INLINE_TF = """\
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:logging handled centrally
  bucket = "logs" # tfsec:ignore:aws-s3-enable-logging
  // trivy:ignore:AVD-AWS-0089
  acl = "private" #checkov:skip=CKV_AWS_20 checkov:skip=CKV_AWS_21
}
"""


def _write_tf(tmp_path, rel="mod/main.tf", text=INLINE_TF):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_find_inline_skips_all_directives(tmp_path):
    _write_tf(tmp_path)
    found = sa.find_inline_skips(str(tmp_path))
    assert [(s.line, s.directive, s.check_id) for s in found] == [
        (2, "checkov:skip=", "CKV_AWS_18"),
        (3, "tfsec:ignore:", "aws-s3-enable-logging"),
        (4, "trivy:ignore:", "AVD-AWS-0089"),
        (5, "checkov:skip=", "CKV_AWS_20"),
        (5, "checkov:skip=", "CKV_AWS_21"),
    ]


def test_find_inline_skips_ignores_code_and_vendored_dirs(tmp_path):
    _write_tf(tmp_path, "main.tf", 'locals { x = "checkov:skip=CKV_AWS_1" }\n')
    _write_tf(tmp_path, ".terraform/modules/m/main.tf", "#checkov:skip=CKV_AWS_2\n")
    _write_tf(tmp_path, "notes.md", "#checkov:skip=CKV_AWS_3\n")
    assert sa.find_inline_skips(str(tmp_path)) == []


def test_unwaived_inline_skip_is_error(tmp_path):
    _write_tf(tmp_path, text="#checkov:skip=CKV_AWS_18\n")
    res = sa.validate([], TODAY)
    sa.audit_inline(res, sa.find_inline_skips(str(tmp_path)), "error")
    assert not res.ok
    assert res.errors[0].line == 1 and res.errors[0].path.endswith("main.tf")
    assert "CKV_AWS_18" in res.errors[0].message


def test_inline_skip_covered_by_directory_waiver(tmp_path):
    tf = _write_tf(tmp_path, text="#checkov:skip=CKV_AWS_18\n")
    rows = sa.parse_suppressions([_sup(paths=[str(tf.parent)])])
    res = sa.validate(rows, TODAY)
    sa.audit_inline(res, sa.find_inline_skips(str(tmp_path)), "error")
    assert res.ok


def test_inline_skip_covered_by_file_waiver(tmp_path):
    tf = _write_tf(tmp_path, text="#checkov:skip=CKV_AWS_18\n")
    res = sa.validate(sa.parse_suppressions([_sup(paths=[str(tf)])]), TODAY)
    sa.audit_inline(res, sa.find_inline_skips(str(tmp_path)), "error")
    assert res.ok


def test_inline_skip_needs_same_id_and_covering_path(tmp_path):
    tf = _write_tf(tmp_path, text="#checkov:skip=CKV_AWS_18\n")
    other = tmp_path / "mod-other"  # shares a prefix, but is not a parent
    rows = sa.parse_suppressions(
        [_sup(id="CKV_AWS_21", paths=[str(tf.parent)]), _sup(paths=[str(other)])]
    )
    res = sa.validate(rows, TODAY)
    sa.audit_inline(res, sa.find_inline_skips(str(tmp_path)), "error")
    assert len(res.errors) == 1


def test_expired_waiver_does_not_cover_inline_skip(tmp_path):
    tf = _write_tf(tmp_path, text="#checkov:skip=CKV_AWS_18\n")
    rows = sa.parse_suppressions([_sup(paths=[str(tf.parent)], expires="2026-01-01")])
    res = sa.validate(rows, TODAY)
    sa.audit_inline(res, sa.find_inline_skips(str(tmp_path)), "error")
    assert sum(1 for p in res.errors if p.path) == 1


def test_inline_warn_level_does_not_fail(tmp_path):
    _write_tf(tmp_path, text="#tfsec:ignore:aws-s3-enable-logging\n")
    res = sa.validate([], TODAY)
    sa.audit_inline(res, sa.find_inline_skips(str(tmp_path)), "warn")
    assert res.ok
    assert len(res.warnings) == 1


def test_trivy_avd_id_is_a_valid_waiver_id():
    res = sa.validate(sa.parse_suppressions([_sup(id="AVD-AWS-0089")]), TODAY)
    assert res.ok


def test_inline_sarif_points_at_tf_line(tmp_path):
    _write_tf(tmp_path, text="\n#trivy:ignore:AVD-AWS-0089\n")
    res = sa.validate([], TODAY)
    sa.audit_inline(res, sa.find_inline_skips(str(tmp_path)), "error")
    result = sa.to_sarif(res, "supp.yaml")["runs"][0]["results"][0]
    assert result["ruleId"] == "suppression-audit/inline-skip"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"].endswith("main.tf")
    assert loc["region"]["startLine"] == 2


def test_main_scan_inline_levels(tmp_path, capsys):
    import yaml
    _write_tf(tmp_path, text="#checkov:skip=CKV_AWS_18\n")
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump([_sup(id="CKV_AWS_21")]))
    base = ["--file", str(p), "--today", "2026-08-19", "--scan-inline", str(tmp_path)]

    assert sa.main(base) == 1
    out = capsys.readouterr().out
    assert "1 inline skip(s), 0 covered by a waiver" in out
    assert "main.tf:1 [CKV_AWS_18]" in out

    assert sa.main(base + ["--inline", "warn"]) == 0
    assert "warn  " in capsys.readouterr().out

    assert sa.main(base + ["--inline", "off"]) == 0
    assert "inline skip" not in capsys.readouterr().out


def test_main_scan_inline_missing_dir_exit_two(tmp_path):
    import yaml
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump([_sup()]))
    assert sa.main(["--file", str(p), "--scan-inline", str(tmp_path / "nope")]) == 2


def test_main_empty_waiver_file_still_scans_inline(tmp_path):
    _write_tf(tmp_path, text="#checkov:skip=CKV_AWS_18\n")
    assert sa.main(["--file", os.devnull, "--scan-inline", str(tmp_path)]) == 1
