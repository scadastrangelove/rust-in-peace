// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
//
// tls_unpin.js — neutralize common Android certificate pinning so the
// mitm_observe network capture can proceed.
//
//   supports:   plan mitm_network_observe  (capability cleartext_tls, §A5)
//   tier:       B — heavy_instrumented (Frida + emulator)  --  the ESCALATION
//               mitm_observe.md takes when Tier-A proxying is blocked by pinning.
//   earns:      with the pin off, the proxy decrypts the session -> the promoted
//               witness is dynamic_observation / heavy_instrumented STRENGTH 3.
//
// This is a TESTING AID for AUTHORIZED DEFENSIVE ASSESSMENT: it turns off the
// app's TLS trust checks in a controlled emulator so an assessor can read the
// payload of a request the finding is about. It observes nothing by itself —
// pair it with mitm_observe.md's proxy capture, which is the actual oracle.
//
//   frida -U -f <PACKAGE> -l tls_unpin.js --no-pause     # spawn + unpin, or
//   frida -U -n <PACKAGE> -l tls_unpin.js                # attach to a running app
//
// HONESTY GATE (mitm_observe.md "When the pin actually holds"): if the FINDING
// CLAIM was "this endpoint is unpinned/cleartext" and pinning is what stopped
// your capture, the pin HOLDING refutes the finding -> report guard_held; do NOT
// unpin and then claim "cleartext observed". Unpin only to characterize a payload
// on an endpoint whose pinning is not the guard under test, and record in the
// promotion <detail> which pin layer you bypassed.
//
// Each hook logs the layer it engaged; the set of engaged layers is EVIDENCE of
// the app's real TLS posture (which pin was present) for the witness.

Java.perform(function () {
    var engaged = [];
    function ts() { return new Date().toISOString(); }
    function mark(layer, ctx) {
        engaged.push(layer);
        console.log('[' + ts() + '][unpin] ' + layer + (ctx ? ' :: ' + ctx : ''));
    }

    // 1) OkHttp3 CertificatePinner.check(...) — the most common app-level pin.
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overloads.forEach(function (ov) {
            ov.implementation = function () {
                mark('okhttp3.CertificatePinner.check',
                     arguments.length ? String(arguments[0]) : '');
                return;   // every check(...) overload is void — accept the chain
            };
        });
    } catch (e) { /* OkHttp / this pin not present */ }

    // 2) Hostname verification (OkHttp + javax) — make verify() accept.
    ['okhttp3.internal.tls.OkHostnameVerifier',
     'com.android.okhttp.internal.tls.OkHostnameVerifier'].forEach(function (cls) {
        try {
            var V = Java.use(cls);
            V.verify.overloads.forEach(function (ov) {
                ov.implementation = function () { mark(cls + '.verify -> true'); return true; };
            });
        } catch (e) { /* not present */ }
    });

    // 3) Conscrypt TrustManagerImpl — the platform trust check under the socket.
    //    checkTrustedRecursive (API 24+) / verifyChain (older) return the trusted
    //    chain; returning it unconditionally accepts any server cert.
    try {
        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        var EmptyList = Java.use('java.util.ArrayList');
        if (TMI.checkTrustedRecursive) {
            TMI.checkTrustedRecursive.implementation = function () {
                mark('conscrypt.TrustManagerImpl.checkTrustedRecursive -> []',
                     arguments.length >= 4 ? String(arguments[3]) : '');
                return EmptyList.$new();
            };
        }
        if (TMI.verifyChain) {
            TMI.verifyChain.implementation = function (certChain) {
                mark('conscrypt.TrustManagerImpl.verifyChain -> pass');
                return certChain;   // legacy signature returns the chain
            };
        }
    } catch (e) { /* not present on this ROM */ }

    // 4) Swap a permissive X509TrustManager into every SSLContext.init — covers
    //    custom TrustManager / disabled-verification code paths (§A5).
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var Permissive = Java.registerClass({
            name: 'org.assessment.PermissiveX509TM',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {
                    return Java.array('java.security.cert.X509Certificate', []);
                }
            }
        });
        var tms = [Permissive.$new()];
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
            mark('javax.net.ssl.SSLContext.init -> permissive TrustManager');
            this.init(km, tms, sr);
        };
    } catch (e) { /* framework SSL not reachable */ }

    // 5) WebView TLS errors — proceed past a bad cert in an in-app WebView.
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            mark('android.webkit.WebViewClient.onReceivedSslError -> proceed()');
            handler.proceed();
        };
    } catch (e) { /* no custom WebViewClient */ }

    // Report which layers were actually present a few seconds in — the witness's
    // record of the app's real pinning posture.
    setTimeout(function () {
        console.log('[' + ts() + '][unpin] layers engaged: ' +
                    (engaged.length ? engaged.join(', ') : 'NONE — app was not pinning'));
    }, 4000);
});
