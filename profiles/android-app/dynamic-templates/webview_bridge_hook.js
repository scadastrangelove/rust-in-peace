// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
//
// webview_bridge_hook.js — promote an android:webview-js-bridge finding from a
// static reachability ARGUMENT to an OBSERVED native call.
//
//   plan:       frida_bridge_hook          (find_to_fuzz.py _FRIDA_BRIDGE)
//   capability: webview_bridge             (capabilities.md §A3)
//   tier:       B — heavy_instrumented (Frida + emulator)
//   earns:      dynamic_observation / heavy_instrumented  ->  STRENGTH 3
//   domain:     behavior
//
// The witness this produces is an OBSERVATION OF THE SINK FIRING: the
// @JavascriptInterface method invoked with WEB-CONTROLLED arguments, driven by
// the loaded page. "Frida attached" is NOT the witness; a logged bridge call
// with its args and Java stack is.
//
// Drive:
//   frida -U -f <PACKAGE> -l webview_bridge_hook.js --no-pause   # spawn, or
//   frida -U -n <PACKAGE> -l webview_bridge_hook.js              # attach
//   then reach the bridge from web content: open the deeplink / redirect / http
//   page that runs  window.<iface>.<method>(...)  in the target WebView.
//
// OBSERVE:
//   each "[BRIDGE] <class>.<method>(...)" line is one native call the web
//   content triggered -- the sink. Re-drive the SAME page/URI three times and
//   confirm the SAME call fires 3/3.  Feed promote.py an Observation:
//       effect_observed = true            (the bridge method fired)
//       runs / of_runs   = 3 / 3          (the 3/3 determinism bar)
//       guard_blocked    = false          (true if the load was refused, below)
//       evidence         = the [BRIDGE] line + [LOAD] URL that drove it
//   A 3/3 effect promotes to strength 3.
//
// A BLOCKED probe is a WIN, not a failure: if a strict URL allowlist stops the
// load ([LOAD] never reaches the attacker origin) or the bridge is unreachable
// from the loaded content ([BRIDGE] never fires), the path is REFUTED -- report
// guard_held (Observation.guard_blocked = true). Do NOT dress a bridge that
// never fired as an observation.
//
// FOR AUTHORIZED DEFENSIVE ASSESSMENT ONLY.

// ── <PLACEHOLDER> — the bridge from the finding (§A3 sink site) ───────────────
// The class backing the @JavascriptInterface object, e.g. "com.example.JsBridge".
// If you don't know it, leave BRIDGE_CLASS null: the addJavascriptInterface hook
// below prints "window.<name> -> <class>" as the app registers it, so you can
// fill it in and re-run.
var BRIDGE_CLASS  = null;   // <PLACEHOLDER> e.g. 'com.example.app.JsBridge'
var BRIDGE_METHOD = null;   // <PLACEHOLDER> exact method, or null = every
                            // @JavascriptInterface-annotated method on the class

function ts() { return new Date().toISOString(); }

Java.perform(function () {

    // 1) DISCOVER — log every bridge as it is registered. Reveals the JS-visible
    //    name and the backing class so an unknown BRIDGE_CLASS can be filled in,
    //    and is itself intel about the exposed surface.
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String')
            .implementation = function (obj, name) {
                console.log('[' + ts() + '][REGISTER] window.' + name + ' -> ' +
                            obj.$className);
                if (BRIDGE_CLASS === null) {
                    // auto-hook the just-registered bridge if none was configured
                    hookBridge(obj.$className);
                }
                return this.addJavascriptInterface(obj, name);
            };
    } catch (e) { console.log('[skip] addJavascriptInterface: ' + e); }

    // 2) DRIVE CONTEXT — log the content that reaches the bridge (the attacker-
    //    influenced URL). This ties the observed call back to the entry point.
    try {
        var WV = Java.use('android.webkit.WebView');
        ['loadUrl', 'loadData', 'loadDataWithBaseURL', 'postUrl', 'evaluateJavascript']
            .forEach(function (m) {
                if (WV[m] === undefined) return;
                WV[m].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        console.log('[' + ts() + '][LOAD] WebView.' + m + '(' +
                                    (arguments.length ? String(arguments[0]) : '') + ')');
                        return ov.apply(this, arguments);
                    };
                });
            });
    } catch (e) { console.log('[skip] WebView.load*: ' + e); }

    // 3) THE SINK — hook the bridge method(s). Fire = an observed native call.
    if (BRIDGE_CLASS !== null) hookBridge(BRIDGE_CLASS);
});

// Hook every @JavascriptInterface-eligible method on `className` (or just
// BRIDGE_METHOD if set). Each invocation is logged with args, return, and the
// Java stack (page -> bridge -> sink), matching the static entry->sink path.
function hookBridge(className) {
    try {
        var Bridge = Java.use(className);
        var JsAnno = Java.use('android.webkit.JavascriptInterface');
        var Throwable = Java.use('java.lang.Throwable');
        var Log = Java.use('android.util.Log');

        // Enumerate the annotated (JS-reachable) method names via reflection.
        var names = {};
        var declared = Bridge.class.getDeclaredMethods();
        for (var i = 0; i < declared.length; i++) {
            var mn = declared[i].getName();
            if (BRIDGE_METHOD && mn !== BRIDGE_METHOD) continue;
            // API 17+: only @JavascriptInterface methods are exposed to JS.
            var annotated = false;
            try { annotated = declared[i].isAnnotationPresent(JsAnno.class); } catch (e) {}
            if (BRIDGE_METHOD || annotated) names[mn] = true;
        }

        Object.keys(names).forEach(function (name) {
            var m = Bridge[name];
            if (!m || !m.overloads) return;
            m.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var args = Array.prototype.slice.call(arguments).map(String);
                    console.log('[' + ts() + '][BRIDGE] ' + className + '.' + name +
                                '(' + args.join(', ') + ')');
                    var rv = ov.apply(this, arguments);
                    console.log('[' + ts() + '][BRIDGE] ' + name + ' -> ' + String(rv));
                    console.log(Log.getStackTraceString(Throwable.$new()));   // hop trace
                    return rv;
                };
            });
            console.log('[' + ts() + '][HOOK] ' + className + '.' + name);
        });
    } catch (e) { console.log('[FAIL] hooking ' + className + ': ' + e); }
}
