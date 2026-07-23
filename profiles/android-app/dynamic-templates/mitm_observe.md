<!-- Copyright 2026 Anthropic PBC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# mitm_observe — cleartext / unpinned auth traffic on the wire

Promotes an **`android:cleartext-endpoint`** finding from a static reachability
argument to an **observed** effect: the token-bearing request captured *in
cleartext on the wire*.

|            |                                                              |
| ---------- | ------------------------------------------------------------ |
| plan       | `mitm_network_observe`  (`find_to_fuzz.py` `_MITM_NET`)       |
| capability | `cleartext_tls`  (`capabilities.md` §A5)                      |
| tier       | **A — light_adb** baseline (proxy via `settings`) → **strength 2**; escalates to **B — heavy_instrumented** (Frida unpin) → **strength 3** |
| domain     | `network`                                                    |
| witness    | `dynamic_observation` — the sensitive datum readable on the wire, NOT "a proxy ran" |

This is **setup + steps**, not a single script. The device is the oracle: a
request you can read in plaintext (or a downgraded/unpinned TLS session the proxy
decrypts) is the witness; a proxy process that saw nothing is not.

> A blocked capture is a **win**, not a failure. If the app pins its TLS and the
> finding claimed the endpoint was *unpinned*, the pin holding **refutes** the
> finding — report `guard_held`. Escalate to the Frida unpin (Tier B) only to
> characterize a payload the finding is genuinely about, not to manufacture a
> "cleartext" observation the app's real pinning prevents. See
> [When the pin actually holds](#when-the-pin-actually-holds-guard_held-vs-escalate).

## Placeholders (fill from THIS app + finding)

- `<PROXY_HOST>` — the host IP the device can reach the intercepting proxy on
  (mitmproxy / Burp, listening `:8080`). On the same LAN as the device/emulator;
  from an emulator the host is often `10.0.2.2`.
- `<PACKAGE>` — the app's package id (`pm list packages | grep …`).
- `<ENDPOINT_HOST>` / `<PATH>` — the routable host + path the finding's sink calls
  (§A5 sink site); the request you must see carry auth.
- `<AUTH_MARKER>` — the sensitive datum you are looking for on the wire (a bearer
  token prefix, session cookie name, a credential field) — the thing that makes
  the request a finding and not a public GET.

## Setup — intercepting proxy + device egress

```sh
# 0) Start the proxy on the host (separate terminal). mitmproxy dumps flows:
#    mitmdump -w /tmp/flows.mitm --listen-port 8080
adb devices                                   # confirm the device/emulator is up
adb shell pm list packages | grep -i <PACKAGE>

# 1) Route ALL device HTTP(S) through the proxy (Tier A — no instrumentation):
adb shell settings put global http_proxy <PROXY_HOST>:8080

# 2) For https endpoints, install the proxy CA so the proxy can decrypt. On API
#    24+ apps only trust user CAs if their network_security_config opts in — which
#    is exactly the permissive-NSC / debuggable posture a cleartext_tls finding
#    often rests on. For a plain http:// sink you need NO CA: the proxy already
#    sees it in cleartext.
#    (push the proxy's CA as a user cert via Settings > Security > Install cert,
#     or `adb push` it and add it in the CA UI — do not silently trust it system-wide.)
```

## Drive — reproduce the request the finding's sink makes

Trigger the exact flow the static path argued (login, token refresh, an API
call). Prefer the app's own UI/monkey over synthesizing a request, so you observe
what the app *actually* puts on the wire:

```sh
adb shell monkey -p <PACKAGE> -c android.intent.category.LAUNCHER 1   # cold start
# then drive the specific screen (login / sync) by UI or:
adb shell am start -n <PACKAGE>/<component>    # if the flow has a launchable entry
```

## OBSERVE — the sink effect + the 3/3 gate

The effect is the **request readable in cleartext** carrying `<AUTH_MARKER>`:

```sh
# In the proxy: watch the flow to <ENDPOINT_HOST><PATH>. Confirm the request
# is http:// (or an https the proxy DECRYPTED because the app trusts the CA / has
# no pin) AND that <AUTH_MARKER> is present in the clear.
# Grep the dump for the marker as the machine oracle:
#   mitmdump -nr /tmp/flows.mitm | grep -i "<ENDPOINT_HOST>"
#   strings /tmp/flows.mitm | grep -i "<AUTH_MARKER>"
```

Alternative Tier-A capture (no proxy CA, no app trust needed) — a packet capture,
which shows cleartext http bodies directly:

```sh
adb shell "tcpdump -i any -s0 -w /sdcard/cap.pcap host <ENDPOINT_HOST>" &   # needs tcpdump on device/emulator
# drive the flow, then:
adb pull /sdcard/cap.pcap && strings cap.pcap | grep -i "<AUTH_MARKER>"     # cleartext body on the wire
```

**Determinism (3/3):** repeat the drive **three times** and confirm the same
request carries `<AUTH_MARKER>` in cleartext all three. A capture that only
sometimes shows the marker is flaky — not promoted.

### The `Observation` you feed back (`promote.py`)

Map the capture to the fields `promote.promote()` consumes:

| field             | set it to                                                          |
| ----------------- | ----------------------------------------------------------------- |
| `effect_observed` | `true` iff `<AUTH_MARKER>` was readable in cleartext on the wire  |
| `runs` / `of_runs`| `3` / `3` (the identical captures)                                |
| `guard_blocked`   | `true` iff the pin/TLS held and refuted the finding (see below)   |
| `device_available`| `false` only if no device/emulator was reachable                 |
| `evidence`        | the flow line: method + host + path + the marker's location (redact the value) |

A `3/3` `effect_observed` with `guard_blocked=false` promotes to
`dynamic_observation` **strength 2** (Tier A). Escalating through the Frida unpin
below raises it to **strength 3** (Tier B).

## Escalation — Frida unpin (Tier B, strength 3)

If interception fails because the app **pins** its TLS (the proxy shows a failed
handshake / the app errors), and the finding is about the payload rather than the
mere presence of a pin, neutralize the pinning and re-run the capture:

```sh
# emulator + Frida (heavy tier). Load the unpinning aid, then re-drive step "Drive".
frida -U -f <PACKAGE> -l tls_unpin.js --no-pause      # spawn + unpin, or
frida -U -n <PACKAGE> -l tls_unpin.js                 # attach to a running app
```

See [`tls_unpin.js`](tls_unpin.js). It neutralizes OkHttp `CertificatePinner`,
the Conscrypt `TrustManagerImpl`, a custom `SSLContext` TrustManager, hostname
verification, and `WebViewClient.onReceivedSslError`, and logs which pinning
layers were present — that log is itself evidence of the app's TLS posture. With
pinning off the proxy decrypts the session; the promoted witness is now
`tier=heavy_instrumented` **strength 3**, and the escalation is recorded in the
`<detail>` (which pin layer you bypassed).

## When the pin actually holds — `guard_held` vs escalate

Be honest about which case you are in — this is the correctness win the profile
exists to protect:

- **Finding claim = "endpoint is cleartext / unpinned", pin actually holds** → the
  claim is **refuted**. Set `guard_blocked=true`, verdict `guard_held`. Do **not**
  Frida-unpin and then report "cleartext observed": the pin is the guard, and
  bypassing your own guard to claim the bug proves nothing about a real attacker.
- **Finding claim = a payload/downgrade issue on an endpoint that happens to be
  pinned** → the pin is not the guard under test; unpinning is a legitimate
  observation aid. Escalate, capture, promote to strength 3, and state in
  `<detail>` that pinning was bypassed to read the payload.

Distinguish "pinned" from "your user CA wasn't trusted": a `http://` sink needs no
CA at all, and a genuinely unpinned https app decrypts the moment the user CA is
installed. Only a *handshake the app rejects even with the CA present* is a pin.

## Teardown

```sh
adb shell settings put global http_proxy :0        # clear the proxy
# (or) adb shell settings delete global http_proxy
```

Leaving a device proxy set poisons later stages — always clear it.

## See also

- [`tls_unpin.js`](tls_unpin.js) — the Tier-B pinning-bypass aid this runbook
  escalates to.
- [`capabilities.md`](../capabilities.md) §A5 — the `cleartext_tls` gate and the
  AR3 loopback-cleartext FP rule (a cleartext call scoped to `localhost` is not a
  finding — no on-path attacker).
- `find_to_fuzz.py` `_PLAN_PLAYBOOK["mitm_network_observe"]` — the inline recipe
  this file formalizes.
