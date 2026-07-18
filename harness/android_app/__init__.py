# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""The `android-app` profile — application-security review over a decompiled APK.

Unlike cpp/rust, the primary oracle here is not a crash but a *reachability
witness*: an attacker-controlled Android entry point reaching a security-
sensitive sink past insufficient guards, argued over DEX/smali/manifest. See
docs/profiles/android/DECISIONS.md and profiles/android-app/README.md.
"""
