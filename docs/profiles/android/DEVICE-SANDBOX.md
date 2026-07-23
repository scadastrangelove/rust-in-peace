# The device sandbox — running `android-app-dynamic` safely

`android-app-static` produces `static_reachability` witnesses (strength 1). The
`android-app-dynamic` track promotes them to *observed* effects (strength 2/3) by
driving the app on a real Android runtime and watching the sink fire. That runtime
is the hard part: it needs an **emulator or device**, which the pipeline's static
sandbox cannot host. This doc is the isolation design that makes it safe, and the
contract the promotion engine (`harness/android_app/promote.py`) runs against.

See ADR-5 (two dynamic cost tiers) and ADR-8 (this sandbox) in
[`DECISIONS.md`](DECISIONS.md).

## Why the static sandbox does not fit

The find/grade agents run inside a **gVisor container with egress restricted to
the Claude API** (`docs/security.md`, `docs/agent-sandbox.md`). That model
assumes the untrusted thing is *a file the target parses*. It does not host an
Android runtime:

- an AVD emulator needs **KVM / nested virtualization** and a real kernel; gVisor
  intercepts syscalls and does not provide the hardware acceleration an emulator
  needs to boot in a usable time (a software-only emulator is too slow to drive
  the 3/3 observation loop);
- the untrusted thing here is a **whole application** — Dalvik code plus bundled
  native `.so` — that *runs*, opens sockets, writes files, and may try to detect
  or escape its environment. Containing a running app is a different problem than
  reading its bytes.

So `android-app-dynamic` runs in a **separate device sandbox**, and the static
pipeline stays exactly as it is.

## The isolation model

```
┌ host (minimal, KVM-enabled) ───────────────────────────────────────────┐
│  ┌ promotion-agent container (gVisor, egress = adb socket + Claude API) │
│  │    build_reattack agent: crafts the adb/Frida PoC, reads observations │
│  └──────────────┬───────────────────────────────────────────────────────
│                 │ adb over a controlled unix socket / loopback only
│  ┌ AVD emulator (KVM microVM) ── clean snapshot per finding ────────────┐
│  │   the target app runs here; Frida server (Tier B only)               │
│  └──────────────┬───────────────────────────────────────────────────────
│                 │ all app traffic forced through →
│  ┌ on-path proxy (mitmproxy) ── network capture + egress allowlist ─────┐
│  │   records cleartext; blocks the app reaching anything but the         │
│  │   declared test backends (never the real internet / other targets)   │
│  └───────────────────────────────────────────────────────────────────────
└─────────────────────────────────────────────────────────────────────────┘
```

Four boundaries, each doing one job:

1. **The agent is not root on the host.** The promotion agent runs in its own
   gVisor container exactly like a find/grade agent. Its only reach into the
   emulator is `adb` over a controlled socket — it cannot touch the host or the
   KVM control plane. Its egress is the adb socket + the Claude API, nothing else.
2. **The app is contained in the emulator.** The target app runs inside the AVD,
   not on the host. Emulator escape is the residual risk (see below); the host is
   kept minimal and the emulator runs unprivileged.
3. **The app's network is on-path and allow-listed.** All app traffic is forced
   through the proxy (`settings put global http_proxy`, or an iptables/tun
   redirect). The proxy is both the **network-capture** point (where a
   `network_observation` cleartext witness comes from) and the **egress gate**:
   the app can reach only the declared test backends, never the real internet or
   another target. This is the android analog of "egress restricted to the Claude
   API" — the app's blast radius is a controlled network.
4. **State is reset between findings.** Each promotion attempt starts from a
   **clean AVD snapshot** and restores to it afterward, so one PoC never taints
   the next (a written file, a granted permission, a cached token). Snapshot
   restore is also what makes the **3/3 determinism bar** meaningful: the same
   clean state → run the PoC → observe → restore → repeat. An effect that only
   fires 2/3 across identical clean states is flaky, and `promote.py` keeps it
   `contested` rather than promoting it.

## The two device profiles (ADR-5 tiers)

The sandbox ships in two weights, matching the promotion tiers:

| | Tier A — light | Tier B — heavy |
|---|---|---|
| witness strength | 2 (`dynamic_observation/light_adb`) | 3 (`dynamic_observation/heavy_instrumented`) |
| tools | `adb`, `am`, `pm`, `content`, `logcat`, `run-as`, proxy | + **Frida server**, kept-warm emulator, instrumentation |
| boot | headless, snapshot-boot, disposable | warm pool (Frida attach + hooks are slow to set up) |
| plans | `adb_intent_probe`, `adb_deeplink_probe`, `adb_provider_probe`, `adb_storage_observe`, `mitm_network_observe` | `frida_bridge_hook`, TLS-unpin escalation |
| cost | ~free after the emulator boots — the first increment | a real engineering + infra project |

This is why **pure `android-app-static` is the true zero-infra milestone**, Tier A
is the first increment that stands up the *light* device profile, and Tier B is
its own project (the warm Frida pool). Do not conflate the three.

## Determinism, concurrency, and the pool

- **3/3 or it isn't promoted.** `promote.DET_BAR = 3`. The stage restores the
  snapshot and re-observes until the effect is identical 3/3; `Observation.runs`
  carries the count and `promote()` gates on it.
- **Device pool.** N warm emulators let promotions run in parallel (one clean
  snapshot per finding), the same way N find agents run in parallel. The pool
  size is the dynamic-stage concurrency cap.
- **Recorded observations for CI.** Because `promote()` is a pure function of
  `(witness, dispatch, observation)`, the whole promotion path is testable
  without a live emulator: the canary's `run_dynamic` replays a **recorded**
  observation fixture, so CI exercises promotion deterministically and a real
  target swaps the fixture for a live adb/Frida run. This is the same trick the
  static `reach` oracle uses.

## Residual risks (state them, don't hide them)

- **Emulator escape.** A hostile app breaking out of the AVD to the host is rare
  but not impossible. Mitigation: minimal host, unprivileged emulator, per-run
  microVM, no host FS mounted into the emulator.
- **Anti-instrumentation / anti-emulator apps.** Hardened apps detect Frida, an
  emulator, or a proxy CA and refuse to run or hide the vulnerable behavior. A
  blocked observation is reported honestly as `contested`/`device_unavailable`,
  **never** dressed as a clean result. Targets that gate on Play Integrity /
  SafetyNet need a **real device farm** (Corellium ARM cloud or a physical pool),
  not an emulator — that is a deployment choice, not a code change.
- **TLS pinning.** Tier A's proxy capture fails against a pinned+encrypted
  connection; that is the documented escalation to the Tier-B Frida unpin, not a
  false "no cleartext" result.

## What a target declares

A target that opts into dynamic promotion carries, alongside its static config:
the **device profile** it needs (light / heavy), the **test backends** the proxy
allow-lists, and (for TLS capture) the **proxy CA** to trust in the emulator. The
promotion stage reads the finding's capability → `find_to_fuzz.dispatch()` →
tier, and requests the matching device profile from the pool.
