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
