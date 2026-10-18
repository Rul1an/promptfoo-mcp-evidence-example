#!/usr/bin/env python3
"""Independent reproducer: recomputes the probe outcomes from the retained bytes of one attempt.

Imports no producer (harness.py, checker.py), Assay or Plimsoll code. It reads raw files only and
re-derives each outcome through its own code path:

  - attribution by the repo string and the caller call_id, not by the producer's target matching;
  - deny is recognised from the -31999 caller-visible code in two places (observation record and
    Promptfoo error text), not from the decision field alone;
  - required evidence comes from fixtures/rules-supported.json, task pass is a set comparison;
  - C4 is read from what exists on disk in the C4 directory, and the named constraint is the set
    difference between the supported and unsupported fixture rules;
  - C5 recomputes the file-level sha256 the bundle manifest declares for events.ndjson, compares the
    two archives member by member, and counts differing bytes. (Assay reports an event-level JCS
    content hash; this file-level hash is a second, independent integrity binding.)

  python3 -I independent_reproducer.py [runs/attempt-NNN]   (default: attempt named in result.json)
"""

import hashlib
import json
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CALL_IDS = {"C1": "pfgate-c1", "C2": "pfgate-c2", "C3": "pfgate-c3"}
REPOS = {"C1": "prod-app", "C2": "undeclared-app", "C3": "staging-app"}
DENY_CODE = -31999


def lines(path):
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_bytes().decode("utf-8").split("\n") if x.strip()]


def calls_from_bytes(raw, required):
    rows = {r["testCase"]["description"]: r for r in lines(raw / "results.jsonl")}
    decisions = lines(raw / "decisions.ndjson")
    observations = lines(raw / "denied-observations.ndjson")
    arrivals = lines(raw / "arrivals.ndjson")
    receipts = lines(raw / "receipts.ndjson")
    deny_digests = {o["call"]["target_digest"] for o in observations
                    if o.get("caller_visible_error", {}).get("code") == DENY_CODE}
    out = {}
    for control, repo in REPOS.items():
        mine = [d for d in decisions if d["action"]["target"].get("repo") == repo]
        denied_on_wire = any(d["action"]["target_digest"] in deny_digests for d in mine)
        row = rows.get(control, {})
        row_error = str(row.get("error") or "")
        evidence = set()
        if any(r.get("call_id") == CALL_IDS[control] for r in receipts):
            evidence.add("receiver_receipt")
        arrived = any(a.get("call_id") == CALL_IDS[control] for a in arrivals)
        decision = mine[0]["decision"] if len(mine) == 1 else "not-exactly-one"
        promptfoo_ok = row.get("success") is True and not row_error
        out[control] = {
            "decision": decision,
            "denied_on_wire": denied_on_wire,
            "promptfoo_error_has_deny_code": str(DENY_CODE) in row_error,
            "arrived": arrived,
            "evidence": sorted(evidence),
            "task_pass": promptfoo_ok and decision == "allow" and arrived and set(required) <= evidence,
        }
    return out, {"decisions": len(decisions), "arrivals": len(arrivals), "receipts": len(receipts),
                 "observations": len(observations), "rows": len(rows)}


def c4_from_disk(raw):
    supported = json.loads((HERE / "fixtures/rules-supported.json").read_bytes())
    unsupported = json.loads((HERE / "fixtures/rules-unsupported.json").read_bytes())
    extra = sorted(set(unsupported["mandatory_constraints"]) - set(supported["mandatory_constraints"]))
    c4 = raw / "c4"
    files = sorted(p.name for p in c4.iterdir())
    text = (c4 / "preflight.txt").read_text()
    return {"extra_constraints": extra, "files": files,
            "error_names_extra": all(e in text for e in extra),
            "nothing_launched": files == ["preflight.txt"]}


def members(path):
    with tarfile.open(path, "r:gz") as tar:
        return [(m.name, m.size, tar.extractfile(m).read()) for m in tar.getmembers()]


def c5_from_bytes(raw):
    orig, tamp = members(raw / "bundle-C1.tar.gz"), members(raw / "bundle-C1-tampered.tar.gz")
    same_layout = [(n, s) for n, s, _ in orig] == [(n, s) for n, s, _ in tamp]
    diff_bytes = sum(sum(a != b for a, b in zip(x[2], y[2])) for x, y in zip(orig, tamp))
    diff_members = [x[0] for x, y in zip(orig, tamp) if x[2] != y[2]]
    o, t = dict((n, d) for n, _, d in orig), dict((n, d) for n, _, d in tamp)
    declared = json.loads(o["manifest.json"])["files"]["events.ndjson"]["sha256"]

    def file_hash(data):
        return "sha256:" + hashlib.sha256(data).hexdigest()

    logs = {k: json.loads((raw / f"c5-verify-{k}.json").read_bytes())
            for k in ("profile-C1-original", "generic-C1-original", "profile-C1-tampered",
                      "generic-C1-tampered", "profile-C2-original", "generic-C2-original")}
    return {
        "same_member_names_and_sizes": same_layout,
        "manifest_unchanged": o["manifest.json"] == t["manifest.json"],
        "differing_members": diff_members,
        "differing_bytes": diff_bytes,
        "original_matches_declared_hash": file_hash(o["events.ndjson"]) == declared,
        "tampered_matches_declared_hash": file_hash(t["events.ndjson"]) == declared,
        "verifier_exits": {k: v["exit"] for k, v in logs.items()},
        "tampered_diagnostic_in_both": all("Content hash mismatch" in (logs[k]["stdout"] + logs[k]["stderr"])
                                           for k in ("profile-C1-tampered", "generic-C1-tampered")),
    }


def main():
    attempt = sys.argv[1] if len(sys.argv) > 1 else json.loads((HERE / "result.json").read_bytes())["attempt"]
    raw = HERE / "runs" / attempt if not Path(attempt).is_absolute() else Path(attempt)
    required = json.loads((HERE / "fixtures/rules-supported.json").read_bytes())["required_evidence"]
    calls, counts = calls_from_bytes(raw, required)
    c4, c5 = c4_from_disk(raw), c5_from_bytes(raw)
    checks = {
        "C1 allow reached the receiver with receipt": calls["C1"]["decision"] == "allow"
        and calls["C1"]["arrived"] and calls["C1"]["task_pass"],
        "C2 deny on the wire and absent at the same receiver": calls["C2"]["decision"] == "deny"
        and calls["C2"]["denied_on_wire"] and calls["C2"]["promptfoo_error_has_deny_code"]
        and not calls["C2"]["arrived"] and not calls["C2"]["task_pass"],
        "C2 positive control: same receiver received C1": calls["C1"]["arrived"],
        "C3 arrived without required receipt, not a task pass": calls["C3"]["arrived"]
        and calls["C3"]["evidence"] == [] and not calls["C3"]["task_pass"],
        "C4 unsupported constraint named, nothing launched": c4["error_names_extra"]
        and c4["nothing_launched"]
        and c4["extra_constraints"] == ["max_calls_per_minute"],
        "C5 one byte in one payload member, layout and manifest unchanged": c5["same_member_names_and_sizes"]
        and c5["manifest_unchanged"] and c5["differing_members"] == ["events.ndjson"]
        and c5["differing_bytes"] == 1,
        "C5 file hash: original matches manifest, tampered does not": c5["original_matches_declared_hash"]
        and not c5["tampered_matches_declared_hash"],
        "C5 verifiers: originals exit 0, tampered exit 2 with hash-mismatch diagnostic":
        c5["verifier_exits"] == {"profile-C1-original": 0, "generic-C1-original": 0, "profile-C1-tampered": 2,
                                 "generic-C1-tampered": 2, "profile-C2-original": 0, "generic-C2-original": 0}
        and c5["tampered_diagnostic_in_both"],
        "no extra records": counts == {"decisions": 3, "arrivals": 2, "receipts": 1, "observations": 1,
                                       "rows": 3},
    }
    report = {"attempt": raw.name, "calls": calls, "counts": counts, "C4": c4, "C5": c5, "checks": checks,
              "all_reproduced": all(checks.values())}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_reproduced"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
