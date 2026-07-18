.class public Lcom/canary/app/WebViewBridgeActivity;
.super Landroid/app/Activity;
.source "WebViewBridgeActivity.java"

# PLANTED: android:webview-js-bridge — the canary's Tier-B (heavy/Frida) promotion
# target. An exported Activity hosts a WebView with JavaScript enabled and a native
# bridge (addJavascriptInterface "bridge"), then loads a CALLER-CONTROLLED URL. Web
# content reachable that way can call window.bridge.getToken() and exfiltrate the
# session token.
#
# STATIC witness: argues the reachability path (strength 1, contested).
# DYNAMIC promotion (android-app-dynamic, Tier B): Frida-hook the @JavascriptInterface
# method and load a page that reaches it; OBSERVE getToken() fire → dynamic_observation
# heavy_instrumented (strength 3). See profiles/android-app/dynamic-templates/webview_bridge_hook.js.

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    new-instance v0, Landroid/webkit/WebView;
    invoke-direct {v0, p0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V

    # enable JS
    invoke-virtual {v0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v1
    const/4 v2, 0x1
    invoke-virtual {v1, v2}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V

    # sink: expose a native bridge object to untrusted web content
    new-instance v2, Lcom/canary/app/WebViewBridgeActivity$Bridge;
    invoke-direct {v2, p0}, Lcom/canary/app/WebViewBridgeActivity$Bridge;-><init>(Lcom/canary/app/WebViewBridgeActivity;)V
    const-string v3, "bridge"
    invoke-virtual {v0, v2, v3}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V

    # entry: load a caller-controlled URL into the bridged WebView
    invoke-virtual {p0}, Lcom/canary/app/WebViewBridgeActivity;->getIntent()Landroid/content/Intent;
    move-result-object v3
    invoke-virtual {v3}, Landroid/content/Intent;->getDataString()Ljava/lang/String;
    move-result-object v3
    invoke-virtual {v0, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V

    return-void
.end method

# The bridged object. @JavascriptInterface getToken() is callable from any page the
# WebView loads — the method the Tier-B Frida hook observes firing.
.method public getToken()Ljava/lang/String;
    .locals 1
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation
    const-string v0, "session-token"
    return-object v0
.end method
