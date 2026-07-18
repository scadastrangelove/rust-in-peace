.class public Lcom/canary/app/ExportedForwardActivity;
.super Landroid/app/Activity;
.source "ExportedForwardActivity.java"

# PLANTED: android:exported-activity-launch.
#
# This component is exported with NO permission (see AndroidManifest.xml).
# onCreate reads the caller-supplied Intent and its data URI, wraps that URI in a
# fresh VIEW intent WITHOUT any scheme/host allowlist, and forwards it via
# startActivity. A hostile app therefore controls where this app navigates
# (intent redirection / open-redirect over IPC).
#
# entry: getIntent().getData()  -> sink: startActivity(caller-controlled intent).
# The reachability oracle cites the line of each below.

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    # entry: pull the caller-controlled intent, then its data URI (no validation)
    invoke-virtual {p0}, Lcom/canary/app/ExportedForwardActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0

    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v1

    # build a VIEW intent around the attacker URI (no allowlist / no check)
    new-instance v2, Landroid/content/Intent;
    const-string v0, "android.intent.action.VIEW"
    invoke-direct {v2, v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    # sink: forward the caller-controlled intent
    invoke-virtual {p0, v2}, Lcom/canary/app/ExportedForwardActivity;->startActivity(Landroid/content/Intent;)V

    return-void
.end method
