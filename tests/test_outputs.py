"""Acceptance tests for hidden-channel fingerprint reconciliation."""

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ENTRY = os.environ.get("IMPACT_TRACK_ENTRY", "/app/impact_track_identify.py")
PROFILES = [{'surface_id': 'IMPACT-A', 'fingerprint': [0.82, 0.14, 3.2]},
 {'surface_id': 'IMPACT-B', 'fingerprint': [0.69, 0.22, 4.8]},
 {'surface_id': 'IMPACT-C', 'fingerprint': [0.91, 0.08, 2.1]},
 {'surface_id': 'IMPACT-D', 'fingerprint': [0.76, 0.18, 3.9]},
 {'surface_id': 'IMPACT-E', 'fingerprint': [0.8904, 0.1628, 3.437]},
 {'surface_id': 'IMPACT-F', 'fingerprint': [0.8126, 0.2768, 5.498]},
 {'surface_id': 'IMPACT-G', 'fingerprint': [1.1401, 0.1358, 2.58]},
 {'surface_id': 'IMPACT-H', 'fingerprint': [1.0248, 0.2824, 5.044]},
 {'surface_id': 'IMPACT-I', 'fingerprint': [1.172, 0.254, 4.385]},
 {'surface_id': 'IMPACT-J', 'fingerprint': [1.0578, 0.3904, 6.894]}]
READINGS = [{'slot': 'CH-3',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 1.9679999999999997,
  'tangential_delta_m_s': 0.336,
  'spin_delta_rad_s': 7.68,
  'sample_temp_c': 23.0},
 {'slot': 'CH-10',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 1.656,
  'tangential_delta_m_s': 0.528,
  'spin_delta_rad_s': 11.52,
  'sample_temp_c': 23.0},
 {'slot': 'CH-6',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 2.184,
  'tangential_delta_m_s': 0.192,
  'spin_delta_rad_s': 5.04,
  'sample_temp_c': 23.0},
 {'slot': 'CH-13',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 1.8239999999999998,
  'tangential_delta_m_s': 0.432,
  'spin_delta_rad_s': 9.36,
  'sample_temp_c': 23.0},
 {'slot': 'CH-9',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 2.1369599999999997,
  'tangential_delta_m_s': 0.39072,
  'spin_delta_rad_s': 8.2488,
  'sample_temp_c': 23.0},
 {'slot': 'CH-5',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 1.95024,
  'tangential_delta_m_s': 0.6643199999999999,
  'spin_delta_rad_s': 13.1952,
  'sample_temp_c': 23.0},
 {'slot': 'CH-12',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 2.7362399999999996,
  'tangential_delta_m_s': 0.32592,
  'spin_delta_rad_s': 6.192,
  'sample_temp_c': 23.0},
 {'slot': 'CH-8',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 2.45952,
  'tangential_delta_m_s': 0.6777599999999999,
  'spin_delta_rad_s': 12.105599999999999,
  'sample_temp_c': 23.0},
 {'slot': 'CH-4',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 2.8127999999999997,
  'tangential_delta_m_s': 0.6096,
  'spin_delta_rad_s': 10.524,
  'sample_temp_c': 23.0},
 {'slot': 'CH-11',
  'incoming_m_s': 2.4,
  'outgoing_m_s': 2.53872,
  'tangential_delta_m_s': 0.93696,
  'spin_delta_rad_s': 16.5456,
  'sample_temp_c': 23.0}]
EXPECTED_ROWS = [{'slot': 'CH-10', 'surface_id': 'IMPACT-B', 'residual': 0.0},
 {'slot': 'CH-11', 'surface_id': 'IMPACT-J', 'residual': 0.0},
 {'slot': 'CH-12', 'surface_id': 'IMPACT-G', 'residual': 0.0},
 {'slot': 'CH-13', 'surface_id': 'IMPACT-D', 'residual': 0.0},
 {'slot': 'CH-3', 'surface_id': 'IMPACT-A', 'residual': 0.0},
 {'slot': 'CH-4', 'surface_id': 'IMPACT-I', 'residual': 0.0},
 {'slot': 'CH-5', 'surface_id': 'IMPACT-F', 'residual': 0.0},
 {'slot': 'CH-6', 'surface_id': 'IMPACT-C', 'residual': 0.0},
 {'slot': 'CH-8', 'surface_id': 'IMPACT-H', 'residual': 0.0},
 {'slot': 'CH-9', 'surface_id': 'IMPACT-E', 'residual': 0.0}]
OUTPUT_KEYS = ['trial_id', 'status', 'surface_assignments', 'total_residual', 'accepted', 'diagnostic']
LEDGER_KEYS = ['trial_id', 'input_sha256', 'result_sha256', 'total_residual']


def expose_candidate_path(path):
    if Path("/tmp") not in path.parents:
        return
    for ancestor in path.parents:
        if ancestor == Path("/tmp"):
            break
        ancestor.chmod(0o755)
    path.chmod(0o777)


def candidate_command(tmp_path, *arguments):
    expose_candidate_path(tmp_path)
    if os.geteuid() == 0 and Path("/usr/bin/setpriv").is_file():
        return [
            "/usr/bin/setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "--",
            "/usr/local/bin/python3",
            ENTRY,
            *map(str, arguments),
        ]
    return [sys.executable, ENTRY, *map(str, arguments)]


def base_payload():
    return {
        "trial_id": "IMPACT-STD-7",
        "limits": {"max_slots": 12, "residual_ceiling": 0.02},
        "profiles": copy.deepcopy(PROFILES),
        "readings": copy.deepcopy(READINGS),
    }


def invoke(tmp_path, payload=None, ledger=None, raw=None, output_name="result.json"):
    source = tmp_path / "readings.json"
    target = tmp_path / output_name
    if raw is None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
    source.write_bytes(raw.encode("utf-8"))
    command = [str(value) for value in (source, target)]
    if ledger is not None:
        command.append(str(ledger))
    completed = subprocess.run(candidate_command(tmp_path, *command), capture_output=True, text=True, timeout=30)
    return completed, source, target


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_success_writes_aligned_output_quietly(tmp_path):
    """题面：「成功时 stdout 和 stderr 都必须为空，结果文件是唯一成功信号。」"""
    result, _, output = invoke(tmp_path, base_payload())
    assert result.returncode == 0
    assert result.stdout == "" and result.stderr == ""
    assert output.is_file()


def test_global_assignment_is_minimum_residual(tmp_path):
    """题面：「碰撞轨迹通道必须采用总指纹误差最小的全局对应，而不是按读入顺序配对。」"""
    result, _, output = invoke(tmp_path, base_payload())
    document = read(output)
    assert result.returncode == 0
    assert [(row["slot"], row["surface_id"]) for row in document["surface_assignments"]] == [(row["slot"], row["surface_id"]) for row in EXPECTED_ROWS]
    assert [row["residual"] for row in document["surface_assignments"]] == pytest.approx([row["residual"] for row in EXPECTED_ROWS], abs=1e-12)


def test_assignment_rows_have_exact_fields(tmp_path):
    """题面：「每条surface_assignments记录恰好包含 slot、surface_id 和 residual 三个键。」"""
    result, _, output = invoke(tmp_path, base_payload())
    document = read(output)
    assert result.returncode == 0
    assert all(set(row) == {"slot", "surface_id", "residual"} for row in document["surface_assignments"])


def test_output_has_exact_top_level_keys(tmp_path):
    """题面：「结果根对象恰好包含 trial_id、status、surface_assignments、total_residual、accepted 和 diagnostic 六个键。」"""
    result, _, output = invoke(tmp_path, base_payload())
    document = read(output)
    assert result.returncode == 0
    assert list(document) == OUTPUT_KEYS


def test_output_is_compact_utf8_with_single_lf(tmp_path):
    """题面：「结果文件使用紧凑 UTF-8 JSON，末尾只有一个 LF。」"""
    result, _, output = invoke(tmp_path, base_payload())
    raw = output.read_bytes()
    assert result.returncode == 0
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert b": " not in raw and b", " not in raw


def test_total_residual_matches_assignment(tmp_path):
    """题面：「total_residual 是最终对应中所有 residual 之和。」"""
    result, _, output = invoke(tmp_path, base_payload())
    document = read(output)
    total = sum(row["residual"] for row in document["surface_assignments"])
    assert result.returncode == 0
    assert document["total_residual"] == pytest.approx(total, abs=1e-12)
    assert document["total_residual"] == pytest.approx(0.0, abs=1e-10)


def test_ceiling_accepts_inside_case(tmp_path):
    """题面：「总误差不超过 residual_ceiling 时 accepted 为 true。」"""
    payload = base_payload()
    payload["limits"]["residual_ceiling"] = 1.0
    payload["profiles"][0]["fingerprint"] = [value * 1.04 for value in payload["profiles"][0]["fingerprint"]]
    result, _, output = invoke(tmp_path, payload)
    document = read(output)
    assert result.returncode == 0 and document["accepted"] is True
    assert document["status"] == "surfaces_recovered"


def test_ceiling_quarantines_first_outside_value(tmp_path):
    """题面：「总误差超过 residual_ceiling 时仍保留结果，但 accepted 为 false 且 status 为 quarantined。」"""
    payload = base_payload()
    payload["limits"]["residual_ceiling"] = 0.0001
    payload["profiles"][0]["fingerprint"] = [value * 1.04 for value in payload["profiles"][0]["fingerprint"]]
    result, _, output = invoke(tmp_path, payload)
    document = read(output)
    assert result.returncode == 0 and document["accepted"] is False
    assert document["status"] == "quarantined"


def test_missing_top_level_key_is_refused(tmp_path):
    """题面：「顶层缺键时以 1 结束并输出 试验拒收: BAD_IMPACT。」"""
    payload = base_payload()
    payload.pop("limits")
    result, _, output = invoke(tmp_path, payload)
    assert result.returncode == 1 and result.stderr == "试验拒收: BAD_IMPACT\n" and not output.exists()


def test_extra_top_level_key_is_refused(tmp_path):
    """题面：「顶层多键时以 1 结束并输出 试验拒收: BAD_IMPACT。」"""
    payload = base_payload()
    payload["memo"] = "shift"
    result, _, output = invoke(tmp_path, payload)
    assert result.returncode == 1 and result.stderr == "试验拒收: BAD_IMPACT\n" and not output.exists()


def test_duplicate_top_level_key_is_refused(tmp_path):
    """题面：「同一对象出现重复键时按输入损坏处理并输出 试验拒收: BAD_IMPACT。」"""
    payload = base_payload()
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    raw = raw.replace('"trial_id":"', '"trial_id":"duplicate", "trial_id":"', 1) + "\n"
    result, _, output = invoke(tmp_path, raw=raw)
    assert result.returncode == 1 and result.stderr == "试验拒收: BAD_IMPACT\n" and not output.exists()


def test_boolean_numeric_is_refused(tmp_path):
    """题面：「数值字段使用布尔值时不得当作有限数并输出 试验拒收: BAD_IMPACT。」"""
    payload = base_payload()
    payload["readings"][0]["incoming_m_s"] = True
    result, _, output = invoke(tmp_path, payload)
    assert result.returncode == 1 and result.stderr == "试验拒收: BAD_IMPACT\n" and not output.exists()


def test_profile_fingerprint_length_is_refused(tmp_path):
    """题面：「每个指纹必须恰好有三个正有限分量，否则输出 试验拒收: BAD_IMPACT。」"""
    payload = base_payload()
    payload["profiles"][0]["fingerprint"].pop()
    result, _, output = invoke(tmp_path, payload)
    assert result.returncode == 1 and result.stderr == "试验拒收: BAD_IMPACT\n" and not output.exists()


def test_duplicate_slot_is_refused(tmp_path):
    """题面：「`trial_id` 使用 2 至 40 个可打印字符，首尾不得有空白，也不接收控制字符。」"""
    payload = base_payload()
    payload["readings"][1]["slot"] = payload["readings"][0]["slot"]
    result, _, output = invoke(tmp_path, payload)
    assert result.returncode == 1 and result.stderr == "试验拒收: BAD_IMPACT\n" and not output.exists()
    minimum = base_payload()
    minimum["trial_id"] = "AB"
    minimum_result, _, minimum_output = invoke(tmp_path, minimum, output_name="minimum.json")
    assert minimum_result.returncode == 0 and read(minimum_output)["trial_id"] == "AB"
    maximum = base_payload()
    maximum["trial_id"] = "T" * 40
    maximum_result, _, maximum_output = invoke(tmp_path, maximum, output_name="maximum.json")
    assert maximum_result.returncode == 0 and read(maximum_output)["trial_id"] == "T" * 40
    internal_space = base_payload()
    internal_space["trial_id"] = "A B"
    space_result, _, space_output = invoke(tmp_path, internal_space, output_name="space.json")
    assert space_result.returncode == 0 and read(space_output)["trial_id"] == "A B"
    tabbed = base_payload()
    tabbed["trial_id"] = "A\tB"
    tab_result, _, tab_output = invoke(tmp_path, tabbed, output_name="tab.json")
    assert tab_result.returncode == 1 and tab_result.stderr == "试验拒收: BAD_IMPACT\n" and not tab_output.exists()


def test_ledger_has_exact_shape_and_is_idempotent(tmp_path):
    """题面：「完全相同的输入和结果再次运行时，留痕簿字节保持不变。」"""
    ledger = tmp_path / "trail.jsonl"
    result, _, output = invoke(tmp_path, payload=base_payload(), ledger=ledger)
    first = ledger.read_bytes()
    second, _, _ = invoke(tmp_path, payload=base_payload(), ledger=ledger)
    item = json.loads(first)
    assert result.returncode == 0 and second.returncode == 0
    assert list(item) == LEDGER_KEYS and first.endswith(b"\n")
    assert ledger.read_bytes() == first and second.stdout == "" and second.stderr == ""


def test_different_result_appends_one_ledger_line(tmp_path):
    """题面：「不同结果成功产生后，留痕簿按成功顺序追加一行。」"""
    ledger = tmp_path / "trail.jsonl"
    first, _, _ = invoke(tmp_path, payload=base_payload(), ledger=ledger)
    changed = base_payload()
    changed["trial_id"] = "IMPACT-STD-8"
    second, _, _ = invoke(tmp_path, payload=changed, ledger=ledger)
    assert first.returncode == 0 and second.returncode == 0
    assert len(ledger.read_bytes().splitlines()) == 2
    assert ledger.read_bytes().endswith(b"\n")


def test_ledger_path_equal_to_output_is_refused(tmp_path):
    """题面：「留痕簿路径与结果路径相同时输出 台架簿拒收: BAD_IMPACT_LEDGER。」"""
    payload = base_payload()
    source = tmp_path / "readings.json"
    target = tmp_path / "same.json"
    source.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    result = subprocess.run(candidate_command(tmp_path, source, target, target), capture_output=True, text=True, timeout=30)
    assert result.returncode == 1 and result.stderr == "台架簿拒收: BAD_IMPACT_LEDGER\n" and not target.exists()


def test_io_failure_preserves_existing_target(tmp_path):
    """题面：「结果目标不可写时输出 归档失败: IMPACT_IO，既有结果保持原样。」"""
    target = tmp_path / "occupied"
    target.mkdir()
    source = tmp_path / "readings.json"
    source.write_text(json.dumps(base_payload(), separators=(",", ":")), encoding="utf-8")
    result = subprocess.run(candidate_command(tmp_path, source, target), capture_output=True, text=True, timeout=30)
    assert result.returncode == 1 and result.stderr == "归档失败: IMPACT_IO\n"
    assert target.exists() and target.is_dir() and not any(target.iterdir()) and "traceback" not in result.stderr.lower()


def test_wrong_argument_count_is_refused(tmp_path):
    """题面：「命令行没有按声明给出输入与结果路径时，以 1 结束并输出 试验拒收: BAD_IMPACT。」"""
    target = tmp_path / "result.json"
    result = subprocess.run(candidate_command(tmp_path), capture_output=True, text=True, timeout=30)
    assert result.returncode == 1 and result.stderr == "试验拒收: BAD_IMPACT\n" and not target.exists()
