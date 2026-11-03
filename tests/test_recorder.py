import json

import pytest

from agentblackbox.recorder import GENESIS_HASH, Recorder, canonical_json, verify_trace
from agentblackbox.secrets import find_secrets, redact_text


def make_trace(tmp_path, n=5):
    path = tmp_path / "t.jsonl"
    rec = Recorder(path, session_id="s1")
    for i in range(n):
        rec.append(kind="call", tool="read_file", args={"path": f"a{i}.txt"}, decision="allow")
    return path, rec


def lines(path):
    return path.read_text().splitlines()


def write_lines(path, ls):
    path.write_text("\n".join(ls) + "\n")


def test_canonical_json_is_stable_and_sorted():
    assert canonical_json({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_clean_trace_verifies(tmp_path):
    path, rec = make_trace(tmp_path)
    res = verify_trace(path)
    assert res.ok and res.count == 5 and res.errors == []
    assert rec.events[0]["prev_hash"] == GENESIS_HASH


def test_hash_chain_links(tmp_path):
    _, rec = make_trace(tmp_path, 3)
    for prev, cur in zip(rec.events, rec.events[1:], strict=False):
        assert cur["prev_hash"] == prev["hash"]


def test_edit_detected(tmp_path):
    path, _ = make_trace(tmp_path)
    ls = lines(path)
    ev = json.loads(ls[2])
    ev["decision"] = "deny"
    ls[2] = json.dumps(ev)
    write_lines(path, ls)
    res = verify_trace(path)
    assert not res.ok and res.errors[0].seq == 2


def test_delete_detected(tmp_path):
    path, _ = make_trace(tmp_path)
    ls = lines(path)
    del ls[1]
    write_lines(path, ls)
    res = verify_trace(path)
    assert not res.ok and res.errors[0].seq == 1


def test_reorder_detected(tmp_path):
    path, _ = make_trace(tmp_path)
    ls = lines(path)
    ls[1], ls[2] = ls[2], ls[1]
    write_lines(path, ls)
    res = verify_trace(path)
    assert not res.ok and res.errors[0].seq == 1


def test_insert_detected(tmp_path):
    path, _ = make_trace(tmp_path)
    ls = lines(path)
    forged = json.loads(ls[1])
    forged["tool"] = "evil"
    ls.insert(2, json.dumps(forged))
    write_lines(path, ls)
    res = verify_trace(path)
    assert not res.ok and res.errors[0].seq == 2


def test_truncated_tail_detected_via_head(tmp_path):
    path, _ = make_trace(tmp_path)
    write_lines(path, lines(path)[:3])
    res = verify_trace(path)
    assert not res.ok
    assert any("head" in e.reason for e in res.errors)


def test_rehashed_chain_still_caught_by_signed_head(tmp_path):
    # An attacker who edits an event AND recomputes every later hash is only
    # caught by the head file (they do not hold the HMAC key).
    path, _ = make_trace(tmp_path)
    evs = [json.loads(x) for x in lines(path)]
    evs[1]["tool"] = "other"
    prev = GENESIS_HASH
    import hashlib

    out = []
    for e in evs:
        e["prev_hash"] = prev
        body = {k: v for k, v in e.items() if k != "hash"}
        e["hash"] = hashlib.sha256((canonical_json(body) + prev).encode()).hexdigest()
        prev = e["hash"]
        out.append(canonical_json(e))
    write_lines(path, out)
    res = verify_trace(path)
    assert not res.ok and any("head" in e.reason for e in res.errors)


def test_forged_head_signature_detected(tmp_path):
    path, _ = make_trace(tmp_path)
    head_path = path.with_name(path.name + ".head")
    head = json.loads(head_path.read_text())
    head["count"] = 99
    head_path.write_text(json.dumps(head))
    assert not verify_trace(path).ok


def test_missing_head_fails(tmp_path):
    path, _ = make_trace(tmp_path)
    path.with_name(path.name + ".head").unlink()
    res = verify_trace(path)
    assert not res.ok and any("head" in e.reason for e in res.errors)


def test_garbage_line_reported(tmp_path):
    path, _ = make_trace(tmp_path, 2)
    write_lines(path, lines(path) + ["not json"])
    assert not verify_trace(path).ok


def test_wrong_key_fails(tmp_path):
    path, _ = make_trace(tmp_path)
    assert not verify_trace(path, key=b"other").ok


def test_refuses_to_overwrite_existing_trace(tmp_path):
    path, _ = make_trace(tmp_path, 1)
    with pytest.raises(FileExistsError):
        Recorder(path, session_id="s")
    Recorder(path, session_id="s", overwrite=True)


def test_in_memory_recorder_has_head():
    rec = Recorder(None, session_id="s")
    rec.append(kind="call", tool="t", args={}, decision="allow")
    assert rec.head()["count"] == 1


# ---- redaction -----------------------------------------------------------

AWS = "AKIAIOSFODNN7EXAMPLE"


def test_redaction_format_and_equality_preserved():
    a = redact_text(f"key={AWS} and again {AWS}")
    assert AWS not in a
    assert "[REDACTED:aws_access_key:" in a
    assert a.count(a[a.index("[REDACTED") : a.index("]") + 1]) >= 2  # same value, same marker


def test_different_secrets_get_different_markers():
    a = redact_text("AKIAIOSFODNN7EXAMPLE")
    b = redact_text("AKIAIOSFODNN7EXAMPLF")
    assert a != b


def test_recorder_redacts_args_and_result(tmp_path):
    rec = Recorder(tmp_path / "r.jsonl", session_id="s", canaries=["ABB_CANARY_deadbeef01"])
    ev = rec.append(
        kind="call",
        tool="http_post",
        args={"body": f"{AWS} ABB_CANARY_deadbeef01", "n": [AWS]},
        decision="allow",
    )
    text = (tmp_path / "r.jsonl").read_text()
    assert AWS not in text and "ABB_CANARY_deadbeef01" not in text
    assert "[REDACTED:canary:" in ev["args"]["body"]


def test_base64_encoded_secret_is_redacted():
    import base64

    enc = base64.b64encode(f"token {AWS} here".encode()).decode()
    out = redact_text(f"data={enc}")
    assert enc not in out and "[REDACTED:" in out


def test_find_secrets_types():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    assert {h.kind for h in find_secrets(pem)} == {"private_key"}
    assert find_secrets("the password field is required") == []
    assert find_secrets("password = hunter2hunter2xx")  # assignment with a real-looking value
    assert find_secrets("ghp_" + "a" * 36)


def test_placeholder_assignments_are_not_secrets():
    assert not find_secrets("Set api_key = YOUR_API_KEY_HERE in your config file.")
    assert not find_secrets('password: "<your-password-here>"')
    assert find_secrets("api_key = Zx81QpLm20aBc9d")
