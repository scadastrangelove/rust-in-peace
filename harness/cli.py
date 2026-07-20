# Copyright 2026 Anthropic PBC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""CLI entrypoint.

  vuln-pipeline run <target> --model <model>                   # one find + grade cycle
  vuln-pipeline run <target> --model <m> --runs 8 --parallel   # 8 concurrent, round-robin focus areas
  vuln-pipeline run <target> --model <m> --auto-focus          # recon discovers focus areas first
  vuln-pipeline recon <target> --model <model>                 # standalone: print discovered areas
  vuln-pipeline dedup <results_dir>                            # group crashes by signature
  vuln-pipeline report <results_dir> --model <m> [--novelty]   # exploitability analysis per unique crash

Output: ./results/<target>/<timestamp>/{result.json,find_transcript.jsonl,
grade_transcript.jsonl,poc.bin}; reports → .../reports/bug_NN/

Auth: resolved by ``harness.auth`` (Bedrock / Vertex / ANTHROPIC_API_KEY /
CLAUDE_CODE_OAUTH_TOKEN — one required; see docs/agent-sandbox.md).
Model: --model flag, or VULN_PIPELINE_MODEL env var (required, one or the other).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from . import docker_ops, sandbox
from . import capabilities as caps
from .corpus import save_regression
from .agent import color
from .aggregate import aggregate, format_report as format_aggregate, AGG_MODES
from .artifacts import CrashArtifact, RunResult, ReattackArtifact, RunScorecard
from .profiles import detector_for_output, get_profile
from .config import TargetConfig
from .dedup import dedup
from .rust.find_to_fuzz import run_reattack, dispatch as reattack_dispatch, DEFAULT_REATTACK_MAX_TURNS
from .find import run_find, DEFAULT_FIND_MAX_TURNS
from .grade import run_grade
from .judge import run_judge, run_compare
from .novelty import upstream_log, crash_file_from_frame, NOVELTY_NOT_CHECKED
from .patch import run_patch, PATCH_MAX_TURNS, DEFAULT_MAX_ITERATIONS
from .predisclose import run_maintainer_review, MAINTAINER_REVIEW_MAX_TURNS
from .recon import run_recon, RECON_MAX_TURNS
from .report import run_report, REPORT_MAX_TURNS
from .prompts.system_prompt import build_system_prompt
from .auth import (  # noqa: F401
    resolve_auth_env as _resolve_auth_env,
    warn_bedrock_model as _warn_bedrock_model,
    NO_AUTH_MSG,
)


def _resolve_target_dir(target: str) -> Path:
    """Accept either a name (looked up under ./targets/) or a direct path."""
    p = Path(target)
    if p.exists() and (p / "config.yaml").exists():
        return p.resolve()
    local = Path.cwd() / "targets" / target
    if local.exists() and (local / "config.yaml").exists():
        return local.resolve()
    raise FileNotFoundError(
        f"Target '{target}' not found. Looked at: {p}, {local}"
    )


def _terminate_subprocesses() -> None:
    """SIGKILL all direct children. The SDK's claude subprocess (Node) does not
    die when we do — it gets orphaned to init and keeps executing Bash tool
    calls against whatever container is named find_target. Observed running
    11+ hours after its parent died. Walk /proc, find PPID==us, kill.
    No-op on platforms without /proc (macOS); container cleanup in _on_signal
    still removes the targets the orphan would be exec'ing into."""
    if not os.path.isdir("/proc"):
        return
    me = os.getpid()
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            with open(f"/proc/{entry.name}/stat", "rb") as f:
                # stat format: pid (comm) state ppid ...  — comm can contain spaces/parens,
                # so split on the last ')' to safely get the fields after it.
                after_comm = f.read().rsplit(b")", 1)[1].split()
            ppid = int(after_comm[1])  # state=[0], ppid=[1]
            if ppid == me:
                os.kill(int(entry.name), signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
            pass


_current_target_name: str | None = None


def _on_signal(signum, frame) -> None:
    """Best-effort container cleanup on SIGTERM/SIGINT.

    find.py/grade.py/recon.py have finally: blocks that rm their containers, but
    finally only runs on Python exceptions — not on signals. Without this, a
    SIGTERM leaves containers orphaned (4GB memory reservation each) AND the
    SDK's Node subprocess orphaned to init, still executing tool calls against
    whatever container holds the name. Kill children first, then containers.
    Container names are target-scoped (find_<target>_N, grader_<target>_N,
    recon_<target>, report_<target>_N) so parallel runs on different targets
    don't collide. The filter matches only this process's target.
    """
    print(f"\n[cleanup] signal {signum} received, terminating subprocesses + removing containers", file=sys.stderr)
    _terminate_subprocesses()
    t = _current_target_name or "target"
    r = subprocess.run(
        ["docker", "ps", "-q",
         "--filter", f"name=find_{t}_",
         "--filter", f"name=grader_{t}_",
         "--filter", f"name=recon_{t}",
         "--filter", f"name=report_{t}_"],
        capture_output=True, text=True,
    )
    ids = r.stdout.split()
    if ids:
        subprocess.run(["docker", "rm", "-f", *ids], capture_output=True)
    # Re-raise with default handling so exit code reflects the signal.
    signal.signal(signum, signal.SIG_DFL)
    signal.raise_signal(signum)


_RUN_TERMINAL = {"crash_found", "crash_rejected", "no_crash_found"}


def _load_run_checkpoint(out_dir: Path) -> RunResult | None:
    """Return a prior run's result if it reached a terminal status.

    agent_failed / build_failed / error are NOT terminal — resume retries them.
    Transcripts in result.json are slimmed to strings; reload as empty lists.
    """
    p = out_dir / "result.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if d.get("status") not in _RUN_TERMINAL:
        return None
    d["find_transcript"] = []
    d["grade_transcript"] = []
    return RunResult.from_dict(d)


def _resume_layout_error(results_root: Path, runs: int) -> str | None:
    """Return an error string if --runs is incompatible with the on-disk layout
    of a --resume dir. out_dirs is [root] when runs==1 vs [root/run_NNN] when
    runs>1; mixing the two corrupts dedup/report."""
    n_existing = len(list(results_root.glob("run_[0-9][0-9][0-9]")))
    if n_existing and runs < (need := max(n_existing, 2)):
        return (f"--resume dir has {n_existing} run_* subdir(s) but --runs={runs}; "
                f"pass --runs {need} (or more to extend)")
    if not n_existing and runs > 1 and (results_root / "result.json").exists():
        return (f"--resume dir is a single-run layout (top-level result.json) "
                f"but --runs={runs}; pass --runs 1")
    return None


def _write_result(out_dir: Path, result: RunResult) -> None:
    # out_dir already exists (created before run_find); transcripts already
    # streamed to disk by run_agent. Only poc.bin and result.json left.

    # PoC bytes if we have them
    if result.crash:
        with open(out_dir / "poc.bin", "wb") as f:
            f.write(result.crash.poc_bytes)

    # result.json — strip transcripts to keep it readable (they're in the JSONLs)
    slim = result.to_dict()
    slim["find_transcript"] = f"see find_transcript.jsonl ({len(result.find_transcript)} messages)"
    slim["grade_transcript"] = f"see grade_transcript.jsonl ({len(result.grade_transcript)} messages)"
    # Pipeline-parsed classification: deterministic crash_type / severity /
    # operation. Sits alongside the agent-emitted crash_type so downstream
    # consumers can cross-check (the agent tag is free-text and fragments).
    if result.crash:
        slim["crash"]["reason"] = detector_for_output(result.crash.crash_output).crash_reason(result.crash.crash_output)
    with open(out_dir / "result.json", "w") as f:
        json.dump(slim, f, indent=2)


async def _run_once(
    run_idx: int,
    target: TargetConfig,
    model: str,
    find_only: bool,
    max_turns: int,
    agent_env: dict[str, str],
    out_dir: Path,
    focus_area: str | None,
    found_bugs_path: Path | None,
    stream_ctx: dict | None = None,
    accept_dos: bool = False,
    system_prompt: str | None = None,
) -> RunResult:
    """One find(+grade) attempt. Assumes image is already built.

    Writes result.json to out_dir before returning — stragglers no longer
    block disk writes. If stream_ctx is set, also runs judge→report dispatch
    for graded crashes (passed or rejected) and appends any spawned report
    task to stream_ctx["report_tasks"].
    """
    timings: dict[str, float] = {}
    out_dir.mkdir(parents=True, exist_ok=True)
    find_container = f"find_{target.name}_{run_idx}"
    grade_container = f"grader_{target.name}_{run_idx}"

    def _done(result: RunResult) -> RunResult:
        _write_result(out_dir, result)
        return result

    # Merge static known_bugs with whatever siblings have already landed. The
    # read is best-effort — a missing or half-written file just yields fewer
    # entries, which is fine (the list is advisory).
    known_bugs = list(target.known_bugs)
    if found_bugs_path:
        known_bugs += _read_found_summaries(found_bugs_path)

    # ── Find ─────────────────────────────────────────────────────────────────────────────
    focus_note = f" (focus: {focus_area})" if focus_area else ""
    print(color(f"[find:{run_idx}] Starting find agent (model={model}, max_turns={max_turns}){focus_note} ...", "find"))
    try:
        crash, find_result, find_timings = await run_find(
            target, model=model, max_turns=max_turns, agent_env=agent_env,
            container_name=find_container, focus_area=focus_area,
            known_bugs=known_bugs,
            found_bugs_path=str(found_bugs_path) if found_bugs_path else None,
            transcript_path=str(out_dir / "find_transcript.jsonl"),
            progress_prefix=f"[find:{run_idx}]",
            accept_dos=accept_dos,
            system_prompt=system_prompt,
        )
    except Exception as e:
        traceback.print_exc()
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=None, verdict=None, timings=timings,
            error=f"find agent: {type(e).__name__}: {e}",
        ))
    timings.update(find_timings)
    find_transcript = find_result.transcript()
    resumes = f" ({find_result.resume_count} resume(s))" if find_result.resume_count else ""
    print(f"[find:{run_idx}] done in {timings.get('find', 0):.1f}s, {len(find_transcript)} messages{resumes}")

    # Agent died mid-run (ProcessError, retries exhausted). Transcript preserved.
    if find_result.error:
        print(f"[find:{run_idx}] Agent failed: {find_result.error}")
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=None, verdict=None,
            find_transcript=find_transcript, timings=timings,
            error=f"find agent: {find_result.error}",
        ))

    if crash is None:
        print(f"[find:{run_idx}] No crash artifact emitted.")
        return _done(RunResult(
            target=target.name, status="no_crash_found",
            crash=None, verdict=None,
            find_transcript=find_transcript, timings=timings,
        ))

    print(color(f"[find:{run_idx}] Crash claimed: {crash.crash_type} at {crash.poc_path} ({len(crash.poc_bytes)} bytes)", "red"))

    # <dup_check> is mandatory alongside <poc_path>. The agent makes the
    # judgment (it knows root cause, a regex can't), the pipeline enforces
    # that the judgment happened. Reject before jsonl write so an unchecked
    # crash doesn't pollute siblings' dedup context.
    if crash.dup_check is None:
        print(f"[find:{run_idx}] Rejected: missing <dup_check> tag.")
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=crash, verdict=None,
            find_transcript=find_transcript, timings=timings,
            error="find agent: <dup_check> tag missing — submission rejected",
        ))

    # Record it for siblings before grading — grading can take ~20min and a
    # concurrent agent shouldn't spend that window re-discovering the same bug.
    # Entries are framed as "claims" in the prompt, not confirmed crashes.
    if found_bugs_path:
        _append_found(found_bugs_path, crash, run_idx)

    if find_only:
        return _done(RunResult(
            target=target.name, status="no_crash_found",  # ungraded → not confirmed
            crash=crash, verdict=None,
            find_transcript=find_transcript, timings=timings,
        ))

    # ── Grade ────────────────────────────────────────────────────────────────────
    print(color(f"[grade:{run_idx}] Starting grader agent in fresh container ...", "grade"))
    workspace = out_dir / "grade_workspace"
    try:
        verdict, grade_result, grade_elapsed = await run_grade(
            crash, target, model=model, workspace_dir=str(workspace), agent_env=agent_env,
            container_name=grade_container,
            transcript_path=str(out_dir / "grade_transcript.jsonl"),
            progress_prefix=f"[grade:{run_idx}]",
            system_prompt=system_prompt,
        )
    except Exception as e:
        traceback.print_exc()
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=crash, verdict=None,
            find_transcript=find_transcript, timings=timings,
            error=f"grade agent: {type(e).__name__}: {e}",
        ))
    timings["grade"] = grade_elapsed
    grade_transcript = grade_result.transcript()

    if grade_result.error:
        print(f"[grade:{run_idx}] Agent failed: {grade_result.error}")
        return _done(RunResult(
            target=target.name, status="agent_failed",
            crash=crash, verdict=None,
            find_transcript=find_transcript, grade_transcript=grade_transcript,
            timings=timings, error=f"grade agent: {grade_result.error}",
        ))

    _gline = f"[grade:{run_idx}] done in {grade_elapsed:.1f}s: passed={verdict.passed}, score={verdict.score}"
    print(color(_gline, "bold") if verdict.passed else _gline)

    status = "crash_found" if verdict.passed else "crash_rejected"
    result = RunResult(
        target=target.name, status=status,
        crash=crash, verdict=verdict,
        find_transcript=find_transcript, grade_transcript=grade_transcript,
        timings=timings,
    )
    _write_result(out_dir, result)

    # ── Streaming: judge → report dispatch ───────────────────────────────────────
    # result.json is already on disk — errors here shouldn't clobber it. The
    # find+grade result is the ground truth; judge→report is downstream polish.
    if stream_ctx is not None:
        try:
            await _stream_dispatch(run_idx, target, model, agent_env, crash,
                                   status, verdict.score, stream_ctx)
        except Exception:
            traceback.print_exc()
            print(f"[judge:{run_idx}] stream dispatch failed — result.json preserved")

    return result


async def _stream_dispatch(
    run_idx: int,
    target: TargetConfig,
    model: str,
    agent_env: dict[str, str],
    crash: CrashArtifact,
    grade_status: str,
    grade_score: float,
    ctx: dict,
) -> None:
    """Judge → maybe-report. Serialized on ctx["lock"] so two simultaneous
    arrivals don't both claim NEW for the same root cause. Report dispatch
    happens outside the lock (the slow part)."""
    reports_root: Path = ctx["reports_root"]
    reports_root.mkdir(parents=True, exist_ok=True)
    excerpt = detector_for_output(crash.crash_output).asan_excerpt(crash.crash_output)

    async with ctx["lock"]:
        manifest = _read_manifest(reports_root)
        print(color(f"[judge:{run_idx}] {len(manifest)} bug(s) in manifest ...", "judge"))
        jv, _jr, elapsed = await run_judge(
            asan_excerpt=excerpt, dup_check=crash.dup_check,
            grade_status=grade_status, grade_score=grade_score,
            poc_size=len(crash.poc_bytes),
            manifest_entries=manifest,
            model=model, image_tag=target.image_tag, agent_env=agent_env,
            profile=target.profile,
            container_name=f"judge_{target.name}_{run_idx}",
            transcript_path=str(reports_root / f"judge_run{run_idx:03d}.jsonl"),
            progress_prefix=f"[judge:{run_idx}]",
            system_prompt=ctx["system_prompt"],
        )
        _jline = (f"[judge:{run_idx}] {jv.judgment} in {elapsed:.1f}s"
                  + (f" → bug_{jv.bug_id:02d}" if jv.bug_id is not None else ""))
        print(color(_jline, "red") if jv.judgment == "NEW" else _jline)

        if jv.judgment == "DUP_SKIP":
            _log_judge(reports_root, run_idx, jv, bug_id=jv.bug_id)
            return

        if jv.judgment == "NEW":
            bug_id = _next_bug_id(manifest)
            _append_manifest(reports_root, bug_id, run_idx, excerpt)
        else:  # DUP_BETTER
            bug_id = jv.bug_id
            assert bug_id is not None  # _parse_judge enforces
        _log_judge(reports_root, run_idx, jv, bug_id=bug_id)

    # Lock released — report agent runs without serializing the batch.
    task = asyncio.create_task(_stream_report(
        run_idx, bug_id, crash, target, model, agent_env,
        reports_root, re_report=(jv.judgment == "DUP_BETTER"),
        novelty=ctx["novelty"], max_turns=ctx["report_max_turns"],
        system_prompt=ctx["system_prompt"],
    ))
    ctx["report_tasks"].append(task)


def _log_judge(reports_root: Path, run_idx: int, jv, bug_id: int | None) -> None:
    reports_root.mkdir(parents=True, exist_ok=True)
    with open(reports_root / "judge_log.jsonl", "a") as f:
        f.write(json.dumps({
            "run_idx": run_idx, "judgment": jv.judgment, "bug_id": bug_id,
            "reasoning": jv.reasoning,
        }) + "\n")


def _judged_runs(reports_root: Path) -> set[int]:
    """run_idx values that already passed through _stream_dispatch — the
    idempotence key for --resume --stream replay (one judge_log line per run,
    including DUP_SKIPs)."""
    p = reports_root / "judge_log.jsonl"
    seen: set[int] = set()
    if not p.exists():
        return seen
    for line in p.read_text().splitlines():
        try:
            seen.add(json.loads(line)["run_idx"])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return seen


async def _stream_report(
    run_idx: int,
    bug_id: int,
    crash: CrashArtifact,
    target: TargetConfig,
    model: str,
    agent_env: dict[str, str],
    reports_root: Path,
    re_report: bool,
    novelty: bool,
    max_turns: int,
    system_prompt: str | None,
) -> dict:
    """Write an exploitability report for one crash. If re_report, preserve
    the existing report as report_v1.json and run a compare agent after the
    new one lands."""
    out_dir = reports_root / f"bug_{bug_id:02d}"
    out_dir.mkdir(parents=True, exist_ok=True)

    old_report_text: str | None = None
    if re_report and (out_dir / "report.json").exists():
        # Preserve old one side-by-side; rotate if v1 already taken.
        n = 1
        while (out_dir / f"report_v{n}.json").exists():
            n += 1
        (out_dir / "report.json").rename(out_dir / f"report_v{n}.json")
        try:
            old_report_text = json.loads(
                (out_dir / f"report_v{n}.json").read_text()
            ).get("report", "")
        except (OSError, json.JSONDecodeError):
            old_report_text = None

    frame = detector_for_output(crash.crash_output).top_frame(crash.crash_output) or ""
    crash_file = crash_file_from_frame(frame)
    log = None
    if novelty:
        print(f"[report:{run_idx}→bug_{bug_id:02d}] novelty: fetching upstream log for {crash_file or '?'} ...")
        log = upstream_log(target.github_url, target.commit,
                           crash_file or "", max_bytes=2000)

    print(color(f"[report:{run_idx}→bug_{bug_id:02d}] starting ({len(crash.poc_bytes)}B PoC) ...", "report"))
    try:
        verdict, report_text, result, elapsed = await run_report(
            crash, target, model=model,
            workspace_dir=str(out_dir / "workspace"),
            upstream_log=log, crash_file=crash_file,
            agent_env=agent_env,
            container_name=f"report_{target.name}_{run_idx}",
            max_turns=max_turns,
            transcript_path=str(out_dir / f"report_transcript_run{run_idx:03d}.jsonl"),
            progress_prefix=f"[report:{run_idx}→bug_{bug_id:02d}]",
            system_prompt=system_prompt,
        )
    except Exception as e:
        traceback.print_exc()
        out = {"bug_id": bug_id, "from_run": run_idx, "status": "agent_failed",
               "error": f"{type(e).__name__}: {e}"}
        _write_report_json(out_dir, out)
        return out

    status = "no_report" if verdict is None else "report_submitted"
    if result.error:
        status = "agent_failed"
    _rline = (f"[report:{run_idx}→bug_{bug_id:02d}] done in {elapsed:.1f}s: {status}"
              + (f" rubric={verdict.rubric_score}/10 sev={verdict.severity_rating}"
                 if verdict else ""))
    print(color(_rline, "bold") if status == "report_submitted" else _rline)

    out = {
        "signature": {"crash_type": crash.crash_type, "top_frame": frame},
        "bug_id": bug_id, "from_run": run_idx, "status": status,
        "error": result.error, "elapsed": elapsed,
        "upstream_log": log if log else NOVELTY_NOT_CHECKED,
        "verdict": verdict.to_dict() if verdict else None,
        "report": report_text,
    }
    _write_report_json(out_dir, out)

    # Compare old vs new and record canonical winner.
    if re_report and old_report_text and report_text:
        winner, reasoning, _cr, c_elapsed = await run_compare(
            report_a=old_report_text, report_b=report_text,
            model=model, image_tag=target.image_tag, agent_env=agent_env,
            profile=target.profile,
            container_name=f"compare_{target.name}_{run_idx}",
            transcript_path=str(out_dir / f"compare_run{run_idx:03d}.jsonl"),
            progress_prefix=f"[compare:{run_idx}→bug_{bug_id:02d}]",
            system_prompt=system_prompt,
        )
        print(f"[compare:{run_idx}→bug_{bug_id:02d}] canonical={winner} in {c_elapsed:.1f}s")
        with open(out_dir / "canonical.json", "w") as f:
            json.dump({"winner": winner, "reasoning": reasoning,
                       "a": "prior report", "b": f"run_{run_idx:03d}"}, f, indent=2)

    return out


def _assigned_focus(i: int, focus_areas: list[str]) -> str | None:
    if not focus_areas:
        return None
    return focus_areas[i % len(focus_areas)]


# ── found_bugs.jsonl: runtime bug-sharing ───────────────────────────────────────

def _seed_found_bugs(path: Path, known_bugs: list[str]) -> None:
    """Seed the jsonl with config known_bugs so a mid-run `cat` is a
    complete view, not just peer discoveries. System-prompt attention fades
    at high turn counts; the cat check doesn't."""
    with open(path, "w") as f:
        for kb in known_bugs:
            f.write(json.dumps({"source": "config", "summary": kb}) + "\n")


def _append_found(path: Path, crash: CrashArtifact, run_idx: int) -> None:
    # Raw ASAN excerpt — SUMMARY line + first stack frames. Agents parse the
    # signature themselves; the pipeline doesn't pre-canonicalize crash_type or
    # top_frame anymore (that was a fragility point — adjacent lines, format
    # variance, free-text agent tags all fragmented the dedup).
    entry = {
        "run_idx": run_idx,
        "asan_excerpt": detector_for_output(crash.crash_output).asan_excerpt(crash.crash_output),
    }
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _read_found_summaries(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Config-seeded entries are prose; runtime entries carry ASAN excerpts.
        out.append(d.get("asan_excerpt") or d.get("summary") or "")
    return [s for s in out if s]


# ── reports/manifest.jsonl: streaming-mode judge context ─────────────────────────

def _read_manifest(reports_root: Path) -> list[dict]:
    """Manifest entries with existing report text attached if it's landed."""
    mf = reports_root / "manifest.jsonl"
    if not mf.exists():
        return []
    entries: list[dict] = []
    for line in mf.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        rp = reports_root / f"bug_{e['bug_id']:02d}" / "report.json"
        if rp.exists():
            try:
                e["report_text"] = json.loads(rp.read_text()).get("report", "")
            except (OSError, json.JSONDecodeError):
                e["report_text"] = None
        else:
            e["report_text"] = None
        entries.append(e)
    return entries


def _next_bug_id(entries: list[dict]) -> int:
    if not entries:
        return 0
    return max(e["bug_id"] for e in entries) + 1


def _append_manifest(reports_root: Path, bug_id: int, run_idx: int,
                     excerpt: str) -> None:
    reports_root.mkdir(parents=True, exist_ok=True)
    with open(reports_root / "manifest.jsonl", "a") as f:
        f.write(json.dumps({
            "bug_id": bug_id, "run_idx": run_idx, "asan_excerpt": excerpt,
        }) + "\n")


async def _run_all(
    target: TargetConfig,
    args,
    agent_env: dict[str, str],
    results_root: Path,
) -> list[tuple[Path, RunResult]]:
    """Build once, optionally recon, then dispatch N find+grade cycles."""
    system_prompt = build_system_prompt(args.engagement_context)

    # ── Build (once, shared by all runs) ──────────────────────────────────────────
    print(color(f"[build] Building {target.image_tag} from {target.dockerfile_dir} ...", "dim"))
    t0 = time.time()
    try:
        docker_ops.build(target.dockerfile_dir, target.image_tag)
    except Exception as e:
        results_root.mkdir(parents=True, exist_ok=True)
        err = RunResult(
            target=target.name, status="build_failed",
            crash=None, verdict=None,
            error=f"{type(e).__name__}: {e}",
        )
        return [(results_root, err)]
    print(f"[build] done in {time.time() - t0:.1f}s")

    # ── Focus areas (optional auto-discover via recon) ───────────────────────────
    # focus_areas.json is the checkpoint of record: written on every fresh run,
    # read on every resume regardless of --auto-focus, so a resumed run_NNN gets
    # the same i % len() assignment as the original.
    results_root.mkdir(parents=True, exist_ok=True)
    focus_areas = list(target.focus_areas)
    focus_ckpt = results_root / "focus_areas.json"
    if args.resume and focus_ckpt.exists():
        try:
            focus_areas = json.loads(focus_ckpt.read_text())
            print(f"[resume] {len(focus_areas)} focus area(s) from {focus_ckpt}\n")
        except (OSError, json.JSONDecodeError):
            print(f"[resume] {focus_ckpt} unreadable; falling back to config.yaml list\n")
            focus_ckpt.unlink(missing_ok=True)
    elif args.auto_focus:
        print(color("[recon] Auto-discovering focus areas ...", "recon"))
        discovered, _ = await run_recon(
            target, model=args.model, agent_env=agent_env,
            max_turns=args.recon_max_turns,
            transcript_path=str(results_root / "recon_transcript.jsonl"),
            system_prompt=system_prompt,
        )
        if discovered:
            focus_areas = discovered
            print(color(f"[recon] Discovered {len(discovered)} focus area(s):", "bold"))
            for a in discovered:
                print(color(f"  - {a}", "bold"))
        else:
            print("[recon] No focus areas discovered; using config.yaml list")
        print()
    if not focus_ckpt.exists():
        focus_ckpt.write_text(json.dumps(focus_areas, indent=2))

    # ── Dispatch ─────────────────────────────────────────────────────────────────────────────
    out_dirs = [results_root if args.runs == 1 else results_root / f"run_{i:03d}"
                for i in range(args.runs)]
    # Checkpoint: skip runs whose result.json already landed with a terminal
    # status. agent_failed/error are retried.
    checkpoints: dict[int, RunResult] = {}
    if args.resume:
        for i, d in enumerate(out_dirs):
            if (r := _load_run_checkpoint(d)) is not None:
                checkpoints[i] = r
        if checkpoints:
            print(f"[resume] {len(checkpoints)}/{args.runs} run(s) already terminal "
                  f"({', '.join(f'run_{i:03d}' for i in sorted(checkpoints))}); skipping")
    # Shared file for runtime bug-sharing. Only wire it up for multi-run — a
    # solo agent has no siblings and the concurrent-agents prompt section would
    # just be noise. Absolute path: the agent's cwd is /tmp (find.py), not here.
    found_bugs_path = (results_root / "found_bugs.jsonl").absolute() if args.runs > 1 else None
    if found_bugs_path and not (args.resume and found_bugs_path.exists()):
        _seed_found_bugs(found_bugs_path, target.known_bugs)

    # Streaming: shared judge lock + reports root + task sink. Serialized
    # judge calls mean two simultaneous grade-passes don't both claim NEW for
    # the same bug; report dispatch happens outside the lock.
    stream_ctx: dict | None = None
    judged: set[int] = set()
    if args.stream:
        stream_ctx = {
            "lock": asyncio.Lock(),
            "reports_root": results_root / "reports",
            "report_tasks": [],
            "novelty": args.novelty,
            "report_max_turns": args.report_max_turns,
            "system_prompt": system_prompt,
        }
        if args.resume:
            judged = _judged_runs(stream_ctx["reports_root"])

    async def _checkpointed(i: int) -> RunResult:
        r = checkpoints[i]
        # Replay graded crashes through judge→report so a kill between
        # _write_result and _stream_dispatch doesn't strand them. judge_log
        # is the per-run idempotence key.
        if (stream_ctx is not None and r.crash is not None
                and r.verdict is not None and i not in judged):
            try:
                await _stream_dispatch(i, target, args.model, agent_env, r.crash,
                                       r.status, r.verdict.score, stream_ctx)
            except Exception:
                traceback.print_exc()
                print(f"[judge:{i}] stream dispatch failed — result.json preserved")
        return r

    def _task(i: int):
        if i in checkpoints:
            return _checkpointed(i)
        return _run_once(i, target, args.model, args.find_only, args.max_turns, agent_env,
                         out_dirs[i], _assigned_focus(i, focus_areas), found_bugs_path,
                         stream_ctx, accept_dos=args.accept_dos, system_prompt=system_prompt)

    if args.parallel:
        n_live = args.runs - len(checkpoints)
        print(f"[dispatch] Launching {n_live} run(s) in parallel"
              f"{' (streaming judge→report)' if args.stream else ''} ...\n")
        raw = await asyncio.gather(*[_task(i) for i in range(args.runs)],
                                   return_exceptions=True)
        results: list[RunResult] = []
        for r in raw:
            if isinstance(r, BaseException):
                results.append(RunResult(
                    target=target.name, status="error",
                    crash=None, verdict=None,
                    error=f"{type(r).__name__}: {r}",
                ))
            else:
                results.append(r)
    else:
        results = []
        for i in range(args.runs):
            if i in checkpoints:
                results.append(await _checkpointed(i))
                continue
            print(f"── Run {i + 1}/{args.runs} ──────────────────────────────────────────")
            try:
                r = await _task(i)
            except Exception as e:
                traceback.print_exc()
                r = RunResult(
                    target=target.name, status="error",
                    crash=None, verdict=None,
                    error=f"{type(e).__name__}: {e}",
                )
            results.append(r)

    # Await any report agents spawned during streaming so `run` doesn't exit
    # with orphaned report containers. Errors are captured, not raised.
    if stream_ctx and stream_ctx["report_tasks"]:
        print(f"\n[dispatch] Waiting on {len(stream_ctx['report_tasks'])} report agent(s) ...")
        await asyncio.gather(*stream_ctx["report_tasks"], return_exceptions=True)

    return list(zip(out_dirs, results))


def main() -> int:
    # Line-buffer stdout so progress prints appear immediately when piped/
    # redirected (Python block-buffers by default when not a TTY).
    sys.stdout.reconfigure(line_buffering=True)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    parser = argparse.ArgumentParser(prog="vuln-pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run find+grade against a target")
    p_run.add_argument("target", help="Target name (under ./targets/) or path to target dir")
    p_run.add_argument("--find-only", action="store_true", help="Skip grade stage")
    p_run.add_argument("--runs", type=int, default=None,
                       help="Number of independent runs (default: 5 for profile:rust — the "
                            "measured recall elbow, L13 — else 1). Recall is union-of-N; a "
                            "second derivation of a site is the vote that proves it real.")
    p_run.add_argument("--aggregate", choices=AGG_MODES, default="union",
                       help="Cross-run combiner for the end-of-batch candidate view (default "
                            "union: recall-first, FPs filtered downstream). 'majority' keeps "
                            "only k*2>N — precision-first, NOT recommended for rust.")
    p_run.add_argument("--parallel", action="store_true",
                       help="Run all --runs concurrently (~1GB RAM per run)")
    p_run.add_argument("--auto-focus", dest="auto_focus", action="store_true",
                       help="Run recon agent to auto-discover focus areas (overrides config.yaml)")
    p_run.add_argument("--max-turns", type=int, default=DEFAULT_FIND_MAX_TURNS,
                       help=f"Find-agent turn budget (default {DEFAULT_FIND_MAX_TURNS})")
    p_run.add_argument("--recon-max-turns", type=int, default=RECON_MAX_TURNS,
                       help=f"Recon-agent turn budget for --auto-focus (default {RECON_MAX_TURNS})")
    p_run.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                       help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_run.add_argument("--results-dir", default="./results", help="Output root")
    p_run.add_argument("--resume", type=Path, default=None, metavar="DIR",
                       help="Resume a partially-completed batch dir (results/<target>/<ts>/). "
                            "Runs whose result.json reached a terminal status are skipped; "
                            "agent_failed/error runs are retried. found_bugs.jsonl and "
                            "focus_areas.json are reused, not re-seeded.")
    p_run.add_argument("--stream", action="store_true",
                       help="Stream judge→report as each grade lands. First report shows up "
                            "in minutes, not hours; stragglers don't block disk writes. "
                            "Recommended. Off by default for batch-mode compatibility.")
    p_run.add_argument("--accept-dos", dest="accept_dos", action="store_true",
                       help="Benchmark mode — DoS-class crashes (allocation-size-too-big, "
                            "stack exhaustion, alloc-driven null-derefs) count as valid "
                            "finds; agents won't skip them hunting for memory corruption")
    p_run.add_argument("--novelty", action="store_true",
                       help="(--stream only) Enable host-side upstream novelty check for reports. "
                            "Clones github_url; off by default for air-gapped environments.")
    p_run.add_argument("--report-max-turns", type=int, default=REPORT_MAX_TURNS,
                       help=f"(--stream only) Report-agent turn budget (default {REPORT_MAX_TURNS})")
    p_run.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                       action="store_true",
                       help="Spawn agents under plain runc with no syscall isolation. The "
                            "shipped path is `bin/vp-sandboxed` (gVisor); see "
                            "docs/agent-sandbox.md. Development on a throwaway VM only.")
    p_run.add_argument("--engagement-context", type=Path, default=None,
                       help="Path to an authorization/engagement-scope file injected into the "
                            "agent system prompt. Defaults to a built-in authorized-security-"
                            "research block. Use to supply org-specific scope/disclosure context.")

    p_recon = sub.add_parser("recon", help="Auto-discover focus areas by exploring target source")
    p_recon.add_argument("target", help="Target name (under ./targets/) or path to target dir")
    p_recon.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                         help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_recon.add_argument("--max-turns", type=int, default=RECON_MAX_TURNS,
                         help=f"Recon-agent turn budget (default {RECON_MAX_TURNS})")
    p_recon.add_argument("--engagement-context", type=Path, default=None,
                         help="Path to an authorization/engagement-scope file (see `run --help`)")
    p_recon.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                         action="store_true", help="See `run --help`.")

    p_dedup = sub.add_parser("dedup", help="Group crashes under a results dir by signature")
    p_dedup.add_argument("results_dir", type=Path,
                         help="Directory to walk for result.json files (e.g. results/<target>/)")

    p_report = sub.add_parser("report",
                              help="Generate exploitability reports for unique crashes under a results dir")
    p_report.add_argument("results_dir", type=Path,
                          help="Batch directory (results/<target>/<timestamp>/)")
    p_report.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                          help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_report.add_argument("--parallel", action="store_true",
                          help="Run report agents concurrently")
    p_report.add_argument("--max-turns", type=int, default=REPORT_MAX_TURNS,
                          help=f"Report-agent turn budget (default {REPORT_MAX_TURNS})")
    p_report.add_argument("--only-passed", action="store_true",
                          help="Skip groups where no run passed grading (default: include crash_rejected)")
    p_report.add_argument("--novelty", action="store_true",
                          help="Enable host-side upstream novelty check (clones github_url; "
                               "default off — air-gapped and restricted environments won't need this)")
    p_report.add_argument("--targets-dir", type=Path, default=Path("targets"),
                          help="Where to find target config dirs (default: ./targets)")
    p_report.add_argument("--fresh", action="store_true",
                          help="Ignore existing bug_NN/report.json checkpoints and re-report "
                               "every group. Default: skip groups already at report_submitted.")
    p_report.add_argument("--engagement-context", type=Path, default=None,
                          help="Path to an authorization/engagement-scope file (see `run --help`)")
    p_report.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                          action="store_true", help="See `run --help`.")

    p_patch = sub.add_parser("patch",
                             help="Generate and verify a fix for each unique crash under a results dir")
    p_patch.add_argument("results_dir", type=Path,
                         help="Batch directory (results/<target>/<timestamp>/)")
    p_patch.add_argument("--bug", type=int, default=None,
                         help="Only patch bug_NN (default: all)")
    p_patch.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                         help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_patch.add_argument("--parallel", action="store_true",
                         help="Run patch agents concurrently")
    p_patch.add_argument("--max-turns", type=int, default=PATCH_MAX_TURNS,
                         help=f"Patch-agent turn budget per iteration (default {PATCH_MAX_TURNS})")
    p_patch.add_argument("--max-iterations", type=int, default=DEFAULT_MAX_ITERATIONS,
                         help=f"Fix↔grade iteration cap (default {DEFAULT_MAX_ITERATIONS})")
    p_patch.add_argument("--no-reattack", action="store_true",
                         help="Skip the re-attack tier (T0-T2 only)")
    p_patch.add_argument("--style", action="store_true",
                         help="Run the advisory T3 style judge")
    p_patch.add_argument("--targets-dir", type=Path, default=Path("targets"),
                         help="Where to find target config dirs (default: ./targets)")
    p_patch.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                         action="store_true", help="See `run --help`.")
    p_patch.add_argument("--engagement-context", type=Path, default=None,
                         help="Path to an authorization/engagement-scope file (see `run --help`)")

    p_predisclose = sub.add_parser(
        "predisclose",
        help="Adversarial maintainer-review gate on each bug's report+patch, before disclosure")
    p_predisclose.add_argument("results_dir", type=Path,
                               help="Batch directory (results/<target>/<timestamp>/)")
    p_predisclose.add_argument("--bug", type=int, default=None,
                               help="Only review bug_NN (default: all with a report.json)")
    p_predisclose.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                               help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_predisclose.add_argument("--parallel", action="store_true",
                               help="Run maintainer-review agents concurrently")
    p_predisclose.add_argument("--max-turns", type=int, default=MAINTAINER_REVIEW_MAX_TURNS,
                               help=f"Maintainer-review agent turn budget (default {MAINTAINER_REVIEW_MAX_TURNS})")
    p_predisclose.add_argument("--targets-dir", type=Path, default=Path("targets"),
                               help="Where to find target config dirs (default: ./targets)")
    p_predisclose.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                               action="store_true", help="See `run --help`.")
    p_predisclose.add_argument("--engagement-context", type=Path, default=None,
                               help="Path to an authorization/engagement-scope file (see `run --help`)")

    p_reattack = sub.add_parser(
        "reattack",
        help="find→fuzz bridge (rust): turn findings into reproducing fuzz harnesses")
    p_reattack.add_argument("results_dir", type=Path,
                            help="Batch dir (results/<target>/<ts>/); scorecard + artifacts written here")
    p_reattack.add_argument("--findings", type=Path, default=None,
                            help="JSON list of findings [{finding_id,cwe,site,mechanism,capability,"
                                 "structure_gated,defer_sketch}]. Default: derive from the batch's "
                                 "aggregate candidates (crash_type→CWE).")
    p_reattack.add_argument("--model", default=os.environ.get("VULN_PIPELINE_MODEL"),
                            help="Model string (required; or set VULN_PIPELINE_MODEL)")
    p_reattack.add_argument("--parallel", action="store_true",
                            help="Run reattack agents concurrently")
    p_reattack.add_argument("--max-turns", type=int, default=DEFAULT_REATTACK_MAX_TURNS,
                            help=f"Reattack-agent turn budget (default {DEFAULT_REATTACK_MAX_TURNS})")
    p_reattack.add_argument("--aggregate", choices=AGG_MODES, default="union",
                            help="When deriving findings from the batch, which candidate set (default union)")
    p_reattack.add_argument("--targets-dir", type=Path, default=Path("targets"),
                            help="Where to find target config dirs (default: ./targets)")
    p_reattack.add_argument("--engagement-context", type=Path, default=None,
                            help="Path to an authorization/engagement-scope file (see `run --help`)")
    p_reattack.add_argument("--dangerously-no-sandbox", dest="dangerously_no_sandbox",
                            action="store_true", help="See `run --help`.")

    p_scorecard = sub.add_parser(
        "scorecard",
        help="Render + validate a reattack scorecard (0-bugs-without-a-reason is an error)")
    p_scorecard.add_argument("results_dir", type=Path,
                             help="Batch dir (reads <dir>/reattack/scorecard.json)")

    args = parser.parse_args()

    if args.command in ("run", "recon", "report", "patch", "reattack", "predisclose"):
        if err := sandbox.require(args.dangerously_no_sandbox):
            print(err, file=sys.stderr)
            return 1

    if args.command == "run":
        return _cmd_run(args)
    if args.command == "recon":
        return _cmd_recon(args)
    if args.command == "dedup":
        return _cmd_dedup(args)
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "patch":
        return _cmd_patch(args)
    if args.command == "predisclose":
        return _cmd_predisclose(args)
    if args.command == "reattack":
        return _cmd_reattack(args)
    if args.command == "scorecard":
        return _cmd_scorecard(args)
    return 1


def _cmd_run(args) -> int:
    # Resolve target
    try:
        target_dir = _resolve_target_dir(args.target)
        target = TargetConfig.load(target_dir)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    global _current_target_name
    _current_target_name = target.name

    agent_env = _resolve_auth_env()
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1

    # Model: required, via --model or env
    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model)

    # Runs default is profile-aware AND capability-routed: rust's single-run recall
    # is noisy (L13). If a capabilities.json is present, the per-class vote budget
    # picks N (8 for the high-variance Rudra classes, 3 for stable parsers); else
    # the measured elbow of 5. cpp keeps its historical single run.
    if args.runs is None:
        if target.profile == "rust":
            _inv = caps.load_optional(target.capabilities_path)
            args.runs = _inv.vote_budget() if _inv else caps.DEFAULT_VOTE_BUDGET
        else:
            args.runs = 1

    print(f"Target: {target.name}")
    print(f"  image_tag:   {target.image_tag}")
    print(f"  model:       {args.model}")
    print(f"  binary:      {target.binary_path}")
    print(f"  source_root: {target.source_root}")
    print(f"  max_turns:   {args.max_turns}")
    print(f"  runs:        {args.runs}{' (parallel)' if args.parallel else ''}")
    print(f"  find_only:   {args.find_only}")
    if target.focus_areas and not args.auto_focus:
        print(f"  focus_areas: {len(target.focus_areas)} configured")
    if args.auto_focus:
        print("  auto_focus:  True (recon will discover focus areas)")
    print()

    if args.resume:
        results_root = args.resume
        if not results_root.is_dir():
            print(f"error: --resume dir {results_root} does not exist", file=sys.stderr)
            return 1
        if (err := _resume_layout_error(results_root, args.runs)):
            print(f"error: {err}", file=sys.stderr)
            return 1
        print(f"  resume:      {results_root}")
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        results_root = Path(args.results_dir) / target.name / timestamp

    pairs = asyncio.run(_run_all(target, args, agent_env, results_root))

    print("\n── Summary ────────────────────────────────────────────────────────────────────")
    exit_code = 0
    for i, (out_dir, result) in enumerate(pairs):
        # result.json was already written inside _run_once as each run
        # finished. Rewrite here only for the error-path entries gather
        # synthesized (those never hit _run_once's _done()).
        if result.status == "error":
            _write_result(out_dir, result)
        _sline = f"  run {i}: {result.status:16s} → {out_dir}/result.json"
        print(color(_sline, "red") if result.status == "crash_found" else _sline)
        if result.status != "crash_found":
            exit_code = 2
    if args.stream:
        reports = results_root / "reports"
        n = sum(1 for _ in reports.glob("bug_*/report.json")) if reports.exists() else 0
        print(f"  {n} report(s) → {reports}/")

    # ── Aggregate: union-of-N candidate view (recall-first) ──────────────────
    # Merge the batch's runs into unique (class, site) candidates with vote
    # counts. Written even for a single run (== the dedup view); the value shows
    # at N>1, where a second independent hit is the vote that confirms a find.
    try:
        agg = aggregate(results_root, mode=args.aggregate)
        (results_root / "aggregate.json").write_text(json.dumps(agg.to_dict(), indent=2))
        if agg.candidates:
            print("\n── Aggregate (" + args.aggregate + ") ─────────────────────────────────")
            print(format_aggregate(agg, results_root), end="")
    except Exception as e:
        print(f"[aggregate] skipped: {type(e).__name__}: {e}", file=sys.stderr)
    return exit_code


def _cmd_recon(args) -> int:
    try:
        target_dir = _resolve_target_dir(args.target)
        target = TargetConfig.load(target_dir)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    global _current_target_name
    _current_target_name = target.name

    agent_env = _resolve_auth_env()
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1

    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model)

    print(color(f"[build] Building {target.image_tag} ...", "dim", sys.stderr), file=sys.stderr)
    try:
        docker_ops.build(target.dockerfile_dir, target.image_tag)
    except Exception as e:
        print(f"error: build failed: {e}", file=sys.stderr)
        return 1

    print(color(f"[recon] Exploring {target.source_root} (model={args.model}) ...", "recon", sys.stderr), file=sys.stderr)
    areas, result = asyncio.run(run_recon(
        target, model=args.model, agent_env=agent_env, max_turns=args.max_turns,
        system_prompt=build_system_prompt(args.engagement_context),
    ))

    if result.error:
        print(f"error: recon agent failed: {result.error}", file=sys.stderr)
        return 1
    if not areas:
        print("error: recon agent produced no focus areas", file=sys.stderr)
        return 1

    # YAML fragment to stdout — paste directly into config.yaml
    print("focus_areas:")
    for a in areas:
        escaped = a.replace('"', '\\"')
        print(f'  - "{escaped}"')
    return 0


def _cmd_dedup(args) -> int:
    from .dedup import format_report
    root: Path = args.results_dir
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    groups = dedup(root)
    print(format_report(groups, root), end="")
    return 0 if groups else 2


# ── report ───────────────────────────────────────────────────────────────────

_STATUS_ORDER = {"crash_found": 0, "crash_rejected": 1}


def _pick_representative(entries: list[tuple[Path, str, dict]]) -> tuple[Path, dict, dict]:
    """Pick the best result.json from a dedup group for the report agent.

    Prefer passed-grade > rejected, then highest grade score, then smallest PoC
    (cleaner to analyze). Returns (result_path, result_dict, crash_dict).
    Unreadable entries are skipped; ValueError if nothing is readable.
    """
    candidates: list[tuple[tuple[int, float, int, str], Path, dict, dict]] = []
    for path, status, _reason in entries:
        try:
            r = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        crash = r.get("crash")
        if not crash:
            continue
        score = (r.get("verdict") or {}).get("score") or 0.0
        poc_len = len(crash.get("poc_bytes") or "")
        key = (_STATUS_ORDER.get(status, 2), -score, poc_len, str(path))
        candidates.append((key, path, r, crash))

    if not candidates:
        raise ValueError("no readable result.json in group")
    _k, path, result, crash = min(candidates, key=lambda c: c[0])
    return path, result, crash


async def _report_one(
    idx: int,
    sig: tuple[str, str],
    entries: list[tuple[Path, str, dict]],
    target: TargetConfig,
    args,
    agent_env: dict[str, str],
    reports_root: Path,
) -> dict:
    crash_type, frame = sig
    out_dir = reports_root / f"bug_{idx:02d}"
    out_dir.mkdir(parents=True, exist_ok=True)

    rep_path, _result, crash_dict = _pick_representative(entries)
    crash = CrashArtifact.from_dict(crash_dict)

    crash_file = crash_file_from_frame(frame)
    log = None
    if args.novelty:
        print(f"[report:{idx}] novelty: fetching upstream log for {crash_file or '?'} ...")
        log = upstream_log(target.github_url, target.commit,
                           crash_file or "", max_bytes=2000)

    print(color(f"[report:{idx}] {crash_type} in {frame} "
                f"(from {rep_path.parent.name}, {len(crash.poc_bytes)}B PoC) ...", "report"))

    try:
        verdict, report_text, result, elapsed = await run_report(
            crash, target, model=args.model,
            workspace_dir=str(out_dir / "workspace"),
            upstream_log=log, crash_file=crash_file,
            agent_env=agent_env,
            container_name=f"report_{target.name}_{idx}",
            max_turns=args.max_turns,
            transcript_path=str(out_dir / "report_transcript.jsonl"),
            progress_prefix=f"[report:{idx}]",
            system_prompt=build_system_prompt(args.engagement_context),
        )
    except Exception as e:
        traceback.print_exc()
        out = {"signature": {"crash_type": crash_type, "top_frame": frame},
               "from_run": str(rep_path), "status": "agent_failed",
               "error": f"{type(e).__name__}: {e}"}
        _write_report_json(out_dir, out)
        return out

    status = "no_report" if verdict is None else "report_submitted"
    if result.error:
        status = "agent_failed"
    _rline = (f"[report:{idx}] done in {elapsed:.1f}s: {status}"
              + (f" rubric={verdict.rubric_score}/10 sev={verdict.severity_rating}"
                 if verdict else ""))
    print(color(_rline, "bold") if status == "report_submitted" else _rline)

    out = {
        "signature": {"crash_type": crash_type, "top_frame": frame},
        "from_run": str(rep_path),
        "runs_in_group": [str(p) for p, _s, _r in entries],
        "status": status,
        "error": result.error,
        "elapsed": elapsed,
        "upstream_log": log if log else NOVELTY_NOT_CHECKED,
        "verdict": verdict.to_dict() if verdict else None,
        "report": report_text,
    }
    _write_report_json(out_dir, out)
    return out


def _write_report_json(out_dir: Path, d: dict) -> None:
    with open(out_dir / "report.json", "w") as f:
        json.dump(d, f, indent=2)


def _load_report_checkpoint(out_dir: Path, sig: tuple[str, str]) -> dict | None:
    """Return prior report.json if it landed with status report_submitted AND
    its signature matches. agent_failed / no_report are retried. A signature
    mismatch means bug_NN index drifted (e.g. --resume added new crashes
    between report invocations) and the checkpoint is for a different bug."""
    p = out_dir / "report.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if d.get("status") != "report_submitted":
        return None
    s = d.get("signature", {})
    if (s.get("crash_type"), s.get("top_frame")) != sig:
        return None
    return d


def _cmd_report(args) -> int:
    root: Path = args.results_dir
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    agent_env = _resolve_auth_env()
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1

    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model)

    groups = dedup(root)
    if not groups:
        print("No crashes under results dir.", file=sys.stderr)
        return 2

    # Filter + order: passed groups first, then rejected (or drop if --only-passed).
    def _has_passed(entries): return any(s == "crash_found" for _p, s, _r in entries)
    items = [(sig, ents) for sig, ents in groups.items()
             if not args.only_passed or _has_passed(ents)]
    items.sort(key=lambda kv: (0 if _has_passed(kv[1]) else 1, kv[0]))

    if not items:
        print("No passed-grade crashes (use without --only-passed to include rejected).",
              file=sys.stderr)
        return 2

    # Infer target from the first result.json — all runs in a batch share one target.
    first_path = next(p for _sig, ents in items for p, _s, _r in ents)
    try:
        target_name = json.loads(first_path.read_text())["target"]
        target = TargetConfig.load(args.targets_dir / target_name)
    except Exception as e:
        print(f"error: could not load target config for batch: {e}", file=sys.stderr)
        return 1
    global _current_target_name
    _current_target_name = target.name

    # Build if missing — we're likely on a host that already ran find+grade,
    # but `report` may run standalone against a copied results dir.
    if not docker_ops.image_exists(target.image_tag):
        print(f"[build] Building {target.image_tag} ...")
        docker_ops.build(target.dockerfile_dir, target.image_tag)

    reports_root = root / "reports"
    checkpoints: dict[int, dict] = {}
    if not args.fresh:
        for i, (sig, _ents) in enumerate(items):
            if (r := _load_report_checkpoint(reports_root / f"bug_{i:02d}", sig)) is not None:
                checkpoints[i] = r
    print(f"[report] {len(items)} unique signature(s) → {reports_root}/"
          + (f" ({len(checkpoints)} already reported, skipping)" if checkpoints else ""))
    print(f"  model:   {args.model}")
    print(f"  novelty: {'on (fetches ' + target.github_url + ')' if args.novelty else 'off'}")
    print()

    async def _ckpt(i: int) -> dict:
        print(f"[report:{i}] checkpoint: report_submitted (skipping)")
        return checkpoints[i]

    async def _dispatch():
        tasks = [_ckpt(i) if i in checkpoints
                 else _report_one(i, sig, ents, target, args, agent_env, reports_root)
                 for i, (sig, ents) in enumerate(items)]
        if args.parallel:
            return await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for t in tasks:
            out.append(await t)
        return out

    results = asyncio.run(_dispatch())

    print("\n── Summary ────────────────────────────────────────────────────────────────────")
    exit_code = 0
    for i, r in enumerate(results):
        if isinstance(r, BaseException):
            print(f"  bug_{i:02d}: error — {type(r).__name__}: {r}")
            exit_code = 2
            continue
        status = r.get("status")
        v = r.get("verdict") or {}
        sev = v.get("severity_rating", "-")
        score = v.get("total_score")
        score_s = f" score={score:.2f}" if score is not None else ""
        print(f"  bug_{i:02d}: {status:18s} sev={sev:<10}{score_s}  "
              f"→ {reports_root / f'bug_{i:02d}'}/report.json")
        if status != "report_submitted":
            exit_code = 2
    return exit_code


def _cmd_patch(args) -> int:
    root: Path = args.results_dir
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    agent_env = _resolve_auth_env()
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1
    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model)

    groups = dedup(root)
    if not groups:
        print("No crashes under results dir.", file=sys.stderr)
        return 2

    # Same ordering as _cmd_report so bug_NN here matches reports/bug_NN/
    def _has_passed(ents): return any(s == "crash_found" for _p, s, _r in ents)
    ordered = sorted(groups.items(),
                     key=lambda kv: (0 if _has_passed(kv[1]) else 1, kv[0]))
    items = [(i, sig, ents) for i, (sig, ents) in enumerate(ordered)
             if args.bug is None or i == args.bug]
    if not items:
        print(f"No bug matching --bug {args.bug}.", file=sys.stderr)
        return 2

    first_path = next(p for _i, _s, ents in items for p, _st, _r in ents)
    target_name = json.loads(first_path.read_text())["target"]
    target = TargetConfig.load(args.targets_dir / target_name)
    if not target.build_command:
        print(f"error: target {target.name!r} has no build_command in config.yaml — "
              f"the patch grader needs an in-container rebuild step", file=sys.stderr)
        return 1
    global _current_target_name
    _current_target_name = target.name

    if not docker_ops.image_exists(target.image_tag):
        print(f"[build] Building {target.image_tag} ...")
        docker_ops.build(target.dockerfile_dir, target.image_tag)

    reports_root = root / "reports"
    system_prompt = build_system_prompt(args.engagement_context)

    print(color(f"[patch] {len(items)} bug(s) → {reports_root}/bug_NN/{{patch.diff,patch_result.json}}", "patch"))
    print(f"  model: {args.model}  reattack: {'off' if args.no_reattack else 'on'}  "
          f"iterations≤{args.max_iterations}\n")

    async def _one(idx: int, entries) -> dict:
        out_dir = reports_root / f"bug_{idx:02d}"
        out_dir.mkdir(parents=True, exist_ok=True)
        rep_path, _result, crash_dict = _pick_representative(entries)
        crash = CrashArtifact.from_dict(crash_dict)
        report_json = out_dir / "report.json"
        report_text = (json.loads(report_json.read_text()).get("report")
                       if report_json.exists() else None)
        try:
            diff, verdict, _ = await run_patch(
                crash, target, model=args.model, out_dir=out_dir,
                report_text=report_text,
                max_iterations=args.max_iterations, max_turns=args.max_turns,
                container_name=f"patch_{target.name}_{idx}",
                run_reattack=not args.no_reattack, run_style=args.style,
                agent_env=agent_env, system_prompt=system_prompt,
                progress_prefix=f"[patch:bug_{idx:02d}]",
            )
        except Exception as e:
            traceback.print_exc()
            return {"bug_id": idx, "status": "error", "error": f"{type(e).__name__}: {e}"}
        status = ("no_diff" if diff is None
                  else "patch_verified" if verdict and verdict.passed
                  else "patch_rejected")
        _pline = (f"[patch:bug_{idx:02d}] {status}"
                  + (f"  t0={verdict.t0_builds} t1={verdict.t1_poc_stops} "
                     f"t2={verdict.t2_tests_pass} reattack={verdict.re_attack_clean}"
                     if verdict else ""))
        print(color(_pline, "bold") if status == "patch_verified" else _pline)
        return {"bug_id": idx, "status": status, "from": str(rep_path),
                "verdict": verdict.to_dict() if verdict else None}

    async def _dispatch():
        coros = [_one(i, ents) for i, _sig, ents in items]
        if args.parallel:
            return await asyncio.gather(*coros, return_exceptions=True)
        return [await c for c in coros]

    results = asyncio.run(_dispatch())

    print("\n── Summary ────────────────────────────────────────────────────────────────────")
    exit_code = 0
    for r in results:
        if isinstance(r, BaseException):
            print(f"  error — {type(r).__name__}: {r}")
            exit_code = 2
            continue
        bug_id = r["bug_id"]
        print(f"  bug_{bug_id:02d}: {r['status']:16s} → "
              f"{reports_root}/bug_{bug_id:02d}/patch_result.json")
        if r["status"] != "patch_verified":
            exit_code = 2
    return exit_code


# ── predisclose (P1.3 maintainer-review gate, L13/L15/L23/L34) ──────────────

def _cmd_predisclose(args) -> int:
    root: Path = args.results_dir
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    agent_env = _resolve_auth_env()
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1
    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model)

    reports_root = root / "reports"
    bug_dirs = sorted(d for d in reports_root.glob("bug_*") if d.is_dir())
    items = [(int(d.name.split("_")[1]), d) for d in bug_dirs
             if (d / "report.json").exists()
             and (args.bug is None or int(d.name.split("_")[1]) == args.bug)]
    if not items:
        print("No bug_NN/report.json under results dir "
              "(run `report` — and `patch` for a fix to review — first).", file=sys.stderr)
        return 2

    first_report = json.loads((items[0][1] / "report.json").read_text())
    from_run = first_report.get("from_run")
    if not from_run:
        print("error: report.json missing 'from_run' — can't infer target", file=sys.stderr)
        return 1
    target_name = json.loads(Path(from_run).read_text())["target"]
    target = TargetConfig.load(args.targets_dir / target_name)
    global _current_target_name
    _current_target_name = target.name

    if not docker_ops.image_exists(target.image_tag):
        print(f"[build] Building {target.image_tag} ...")
        docker_ops.build(target.dockerfile_dir, target.image_tag)

    system_prompt = build_system_prompt(args.engagement_context)
    print(color(f"[predisclose] {len(items)} bug(s) → {reports_root}/bug_NN/predisclose.json",
                "patch"))
    print(f"  model: {args.model}\n")

    async def _one(idx: int, out_dir: Path) -> dict:
        report = json.loads((out_dir / "report.json").read_text())
        report_verdict = report.get("verdict") or {}
        patch_diff_path = out_dir / "patch.diff"
        fix_snippet = (patch_diff_path.read_text() if patch_diff_path.exists()
                       else "(no fix proposed)")
        try:
            review, result = await run_maintainer_review(
                finding_text=report.get("report", ""),
                severity_claimed=report_verdict.get("severity_rating", "NOT_STATED"),
                fix_snippet=fix_snippet,
                reachability_arg=report_verdict.get("reachability_verdict", "UNCLEAR"),
                source_root=target.source_root,
                image_tag=target.image_tag,
                model=args.model,
                agent_env=agent_env,
                container_name=f"predisclose_{target.name}_{idx}",
                max_turns=args.max_turns,
                transcript_path=str(out_dir / "predisclose_transcript.jsonl"),
                progress_prefix=f"[predisclose:bug_{idx:02d}]",
                system_prompt=system_prompt,
            )
        except Exception as e:
            traceback.print_exc()
            return {"bug_id": idx, "status": "error", "error": f"{type(e).__name__}: {e}"}

        status = "no_review" if review is None else "reviewed"
        if result.error:
            status = "agent_failed"
        _pline = (f"[predisclose:bug_{idx:02d}] {status}"
                  + (f"  verdict={review.verdict} sev={review.corrected_severity} "
                     f"fix_ok={review.fix_ok}" if review else ""))
        print(color(_pline, "bold") if status == "reviewed" and review.verdict == "ACCEPT"
              else _pline)

        out = {"bug_id": idx, "status": status, "error": result.error,
               "review": review.to_dict() if review else None,
               "fix_reviewed": fix_snippet != "(no fix proposed)"}
        with open(out_dir / "predisclose.json", "w") as f:
            json.dump(out, f, indent=2)
        return out

    async def _dispatch():
        coros = [_one(idx, out_dir) for idx, out_dir in items]
        if args.parallel:
            return await asyncio.gather(*coros, return_exceptions=True)
        return [await c for c in coros]

    results = asyncio.run(_dispatch())

    print("\n── Summary ────────────────────────────────────────────────────────────────────")
    exit_code = 0
    for r in results:
        if isinstance(r, BaseException):
            print(f"  error — {type(r).__name__}: {r}")
            exit_code = 2
            continue
        bug_id = r["bug_id"]
        review = r.get("review") or {}
        verdict = review.get("verdict", "-")
        print(f"  bug_{bug_id:02d}: {r['status']:12s} verdict={verdict:10s} → "
              f"{reports_root}/bug_{bug_id:02d}/predisclose.json")
        if r["status"] != "reviewed" or verdict in ("REJECT", "WONTFIX"):
            exit_code = 2
    return exit_code


# ── reattack (find→fuzz bridge, rust) ────────────────────────────────────────

def _crash_type_to_cwe(crash_type: str | None, operation: str | None) -> str:
    """Map an ASan/panic crash class (what the batch carries) to the CWE that
    drives find_to_fuzz.dispatch. Lossy but deterministic; a --findings file
    with explicit CWEs is preferred when available."""
    ct = (crash_type or "").lower()
    op = (operation or "").upper()
    if "use-after-free" in ct:
        return "CWE-416"
    if "double-free" in ct:
        return "CWE-415"
    if "uninitialized" in ct or "use-of-uninit" in ct:
        return "CWE-908"
    if "race" in ct:
        return "CWE-362"
    if "buffer-overflow" in ct or "buffer-underflow" in ct or "out-of-bounds" in ct:
        return "CWE-787" if op == "WRITE" else "CWE-125"
    if "index" in ct or "slice-range" in ct:
        return "CWE-125"
    if "arith-overflow" in ct or "capacity overflow" in ct:
        return "CWE-190"
    return "CWE-125"   # default OOB


# The most-specific active capability refines dispatch (Miri vs ASan vs compiler).
_CAP_PRIORITY = (
    "unsafe_trait_trust", "unsafe_generic_soundness", "concurrency_async",
    "unsafe_simd", "network_protocol_parser", "subprocess_exec",
    "untrusted_deserialization",
)


def _dominant_capability(inv: "caps.CapabilityInventory | None") -> str | None:
    if inv is None:
        return None
    for cap in _CAP_PRIORITY:
        if inv.is_active(cap):
            return cap
    return None


def _derive_findings(results_root: Path, mode: str) -> list[dict]:
    """Turn a batch's aggregate candidates into reattack findings (crash_type→CWE).
    CONTESTED candidates (flip-flops the static/grade layer didn't settle) are
    listed FIRST — they are the auto-dispatch-to-dynamic case (P1.3)."""
    agg = aggregate(results_root, mode)
    out: list[dict] = []
    for i, c in enumerate(agg.candidates):
        op = c.operations[0] if c.operations else None
        note = "CONTESTED (0 passed, flip-flop) — dynamic verdict authoritative; " if c.is_contested else ""
        out.append({
            "finding_id": f"cand_{i:02d}",
            "cwe": _crash_type_to_cwe(c.crash_type, op),
            "site": c.site,
            "mechanism": f"{note}{c.crash_type} — {c.vote_str()} votes across the batch",
            "contested": c.is_contested,
        })
    # contested first, then by vote order already baked into agg.candidates
    out.sort(key=lambda f: (not f.get("contested", False),))
    return out


def _safe_id(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name))[:80] or "finding"


def _missing_capabilities(inv: "caps.CapabilityInventory | None",
                          arts: list[ReattackArtifact]) -> list[dict]:
    """Every §9 capability the run couldn't fully exercise (P1.1). Two sources:
    active capabilities whose gate needs a non-default sanitizer (MSan/TSan —
    a special sanitizer image), and any reattack whose residual named a missing rung.
    "0 bugs found" is never the whole story; this section is why."""
    out: list[dict] = []
    if inv is not None:
        for g in inv.active_gates():
            if g.sanitizer in ("msan", "tsan"):
                out.append({
                    "capability": g.capability,
                    "evidence": inv.evidence(g.capability),
                    "why_unexercised": f"needs {g.sanitizer.upper()} — not the cargo-fuzz ASan default "
                                       f"(select the matching sanitizer image per fuzzing.md)",
                })
    residual_gaps = {"needs-MSan", "asan-on-C", "grammar-gated", "address-space-only"}
    for a in arts:
        if a.residual_reason in residual_gaps:
            out.append({
                "capability": f"(finding {a.finding_id})",
                "evidence": f"{a.cwe} at reattack template {a.template}",
                "why_unexercised": f"residual={a.residual_reason} — {a.detail or 'see reattack.json'}",
            })
    return out


def _write_scorecard_md(path: Path, sc: RunScorecard, reach: str) -> None:
    lines = [
        f"# Reattack scorecard — {sc.target}",
        "",
        f"{len(sc.reproduced)}/{len(sc.reattacks)} finding(s) reproduced dynamically. "
        f"reachable_from_public_api: **{reach}**.",
        "",
        "| finding | CWE | template | sanitizer | verdict | residual |",
        "|---|---|---|---|---|---|",
    ]
    for a in sc.reattacks:
        lines.append(f"| {a.finding_id} | {a.cwe} | {a.template} | {a.sanitizer} "
                     f"| {a.verdict} | {a.residual_reason} |")
    if sc.missing_capabilities:
        lines += ["", "## Missing capabilities (not a failure — a routing map)", ""]
        for m in sc.missing_capabilities:
            lines.append(f"- **{m['capability']}** — {m['why_unexercised']} "
                         f"(evidence: {m['evidence']})")
    lines.append("")
    path.write_text("\n".join(lines))


def _cmd_reattack(args) -> int:
    root: Path = args.results_dir
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    agent_env = _resolve_auth_env()
    if agent_env is None:
        print(NO_AUTH_MSG, file=sys.stderr)
        return 1
    if not args.model:
        print("error: --model required (or set VULN_PIPELINE_MODEL)", file=sys.stderr)
        return 1
    _warn_bedrock_model(args.model)

    # Findings: explicit JSON, else derive from the batch's aggregate candidates.
    if args.findings:
        try:
            findings = json.loads(args.findings.read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: --findings unreadable: {e}", file=sys.stderr)
            return 1
        if not isinstance(findings, list):
            print("error: --findings must be a JSON list of finding objects", file=sys.stderr)
            return 1
    else:
        findings = _derive_findings(root, args.aggregate)
    if not findings:
        print("No findings to reattack (empty --findings or no aggregate candidates).",
              file=sys.stderr)
        return 2

    # Target: from a result.json in the batch, else a "target" key in the findings.
    first_result = next(root.rglob("result.json"), None)
    target_name = None
    if first_result:
        try:
            target_name = json.loads(first_result.read_text()).get("target")
        except (OSError, json.JSONDecodeError):
            target_name = None
    if not target_name:
        target_name = next((f.get("target") for f in findings if f.get("target")), None)
    if not target_name:
        print("error: could not infer target (no result.json under the batch and no "
              "'target' in findings)", file=sys.stderr)
        return 1
    try:
        target = TargetConfig.load(args.targets_dir / target_name)
    except Exception as e:
        print(f"error: load target {target_name!r}: {e}", file=sys.stderr)
        return 1
    global _current_target_name
    _current_target_name = target.name

    profile = get_profile(target.profile)
    if profile.build_reattack is None:
        print(f"error: profile {target.profile!r} has no dispatch-based reattack — cpp uses "
              f"the static config.reattack_harness (patch stage), not the find→fuzz bridge.",
              file=sys.stderr)
        return 1

    if not docker_ops.image_exists(target.image_tag):
        print(f"[build] Building {target.image_tag} ...")
        docker_ops.build(target.dockerfile_dir, target.image_tag)

    # Capabilities: refine dispatch + record the reachability down-rank.
    inv = caps.load_optional(target.capabilities_path)
    dom_cap = _dominant_capability(inv)
    reach = inv.reachable_from_public_api() if inv else "unknown"
    for f in findings:
        f.setdefault("capability", dom_cap)

    reattack_root = root / "reattack"
    reattack_root.mkdir(parents=True, exist_ok=True)
    print(color(f"[reattack] {len(findings)} finding(s) → {reattack_root}/", "find"))
    print(f"  target: {target.name}  model: {args.model}  capability: {dom_cap or '-'}  "
          f"reachable_from_public_api: {reach}")
    if reach == "no":
        print(color("  note: reachable_from_public_api=no — these are down-ranked "
                    "(unreachable-as-extracted); reattack characterizes, doesn't prioritize.", "dim"))
    system_prompt = build_system_prompt(args.engagement_context)

    async def _one(i: int, f: dict) -> ReattackArtifact:
        fid = _safe_id(f.get("finding_id") or f.get("site") or f"finding_{i}")
        out_dir = reattack_root / fid
        out_dir.mkdir(parents=True, exist_ok=True)
        disp = reattack_dispatch(f.get("cwe"), f.get("capability"),
                                 bool(f.get("structure_gated")))
        print(color(f"[reattack:{i}] {f.get('cwe','?')} @ {f.get('site','?')} "
                    f"→ {disp.template} / {disp.sanitizer}", "report"))
        try:
            art, _res, timings = await run_reattack(
                f, target, model=args.model, max_turns=args.max_turns,
                agent_env=agent_env, container_name=f"reattack_{target.name}_{i}",
                transcript_path=str(out_dir / "reattack_transcript.jsonl"),
                progress_prefix=f"[reattack:{i}]", system_prompt=system_prompt,
            )
        except Exception as e:
            traceback.print_exc()
            art = ReattackArtifact(
                finding_id=fid, cwe=str(f.get("cwe") or "unknown"),
                template=disp.template, sanitizer=disp.sanitizer,
                verdict="build_failed", residual_reason="build-failed",
                detail=f"{type(e).__name__}: {e}")
        out_dir.joinpath("reattack.json").write_text(art.to_json())
        if art.crash_input is not None:
            out_dir.joinpath("crash_input.bin").write_bytes(art.crash_input)
        # Corpus-as-regression: a reproducing crash is persisted so a per-PR
        # replay catches it if it ever returns (P2).
        if art.reproduced and art.crash_input is not None:
            try:
                save_regression(
                    reattack_root / "corpus", finding_id=art.finding_id, cwe=art.cwe,
                    sanitizer=art.sanitizer, crash_input=art.crash_input,
                    reproduction_command=f"cargo +nightly fuzz run reattack (via {art.template})",
                    note=art.detail[:200])
            except Exception as e:
                print(f"[reattack:{i}] corpus save skipped: {type(e).__name__}: {e}", file=sys.stderr)
        _rline = f"[reattack:{i}] {art.verdict} ({art.residual_reason})"
        print(color(_rline, "bold") if art.reproduced else _rline)
        return art

    async def _dispatch():
        coros = [_one(i, f) for i, f in enumerate(findings)]
        if args.parallel:
            return await asyncio.gather(*coros, return_exceptions=True)
        return [await c for c in coros]

    raw = asyncio.run(_dispatch())
    arts: list[ReattackArtifact] = []
    for i, r in enumerate(raw):
        if isinstance(r, BaseException):
            print(f"  reattack {i}: error — {type(r).__name__}: {r}")
            continue
        arts.append(r)

    sc = RunScorecard(target=target.name, reattacks=arts,
                      missing_capabilities=_missing_capabilities(inv, arts))
    (reattack_root / "scorecard.json").write_text(sc.to_json())
    _write_scorecard_md(reattack_root / "SCORECARD.md", sc, reach)

    print("\n── Reattack summary ────────────────────────────────────────────────")
    for a in arts:
        _s = f"  {a.finding_id:16s} {a.verdict:12s} {a.residual_reason:24s} {a.template}"
        print(color(_s, "bold") if a.reproduced else _s)
    print(f"  {len(sc.reproduced)}/{len(arts)} reproduced → {reattack_root}/SCORECARD.md")
    return 0 if sc.reproduced else 2


def _cmd_scorecard(args) -> int:
    """Render + validate a reattack scorecard. Enforces the P1.1 discipline:
    every reattack must carry a residual_reason; a 'clean' verdict without a
    real reason is an ERROR ("0 bugs found" is a lie the reason corrects)."""
    sc_path = args.results_dir / "reattack" / "scorecard.json"
    if not sc_path.exists():
        print(f"error: no scorecard at {sc_path} (run `vuln-pipeline reattack` first)",
              file=sys.stderr)
        return 1
    try:
        sc = RunScorecard.from_dict(json.loads(sc_path.read_text()))
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as e:
        print(f"error: unreadable/invalid scorecard: {e}", file=sys.stderr)
        return 1

    # Validate: no clean-without-residual, and residual matches verdict.
    violations: list[str] = []
    for a in sc.reattacks:
        if a.verdict == "clean" and a.residual_reason in ("reproduced", ""):
            violations.append(f"{a.finding_id}: clean verdict with no residual_reason")
        if a.residual_reason == "uncharacterized":
            violations.append(f"{a.finding_id}: uncharacterized — force a reason before ship")

    print(f"Scorecard — {sc.target}: {len(sc.reproduced)}/{len(sc.reattacks)} reproduced")
    for a in sc.reattacks:
        line = f"  {a.finding_id:18s} {a.verdict:12s} {a.residual_reason:24s} {a.template} [{a.sanitizer}]"
        print(color(line, "bold") if a.reproduced else line)
    if sc.missing_capabilities:
        print("  missing capabilities (routing map, not a failure):")
        for m in sc.missing_capabilities:
            print(f"    - {m.get('capability')}: {m.get('why_unexercised')}")
    if violations:
        print(color(f"\n  DISCIPLINE VIOLATIONS ({len(violations)}):", "red"), file=sys.stderr)
        for v in violations:
            print(f"    ✗ {v}", file=sys.stderr)
        return 2
    print("  ✓ every finding characterized (no clean-without-reason)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
