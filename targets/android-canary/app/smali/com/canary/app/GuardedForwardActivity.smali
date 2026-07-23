.class public Lcom/canary/app/GuardedForwardActivity;
.super Landroid/app/Activity;
.source "GuardedForwardActivity.java"

# DECOY (must be REJECTED). This is deliberately the SAME forwarding pattern as
# ExportedForwardActivity — the code alone looks just as dangerous. The only
# difference lives in the manifest: this component is gated behind a signature-
# level permission (com.canary.app.permission.PRIVILEGED), so only apps signed
# with the same key can reach it. It is therefore NOT attacker-reachable.
#
# A naive scanner flags this as android:exported-no-permission; a rigorous oracle
# rejects it (AR1: the protectionLevel="signature" guard holds). The oracle never
# reaches this smali — it stops at the manifest permission check — but the body is
# kept identical so the lesson is "same code, different guard".

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    invoke-virtual {p0}, Lcom/canary/app/GuardedForwardActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0

    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v1

    new-instance v2, Landroid/content/Intent;
    const-string v0, "android.intent.action.VIEW"
    invoke-direct {v2, v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    invoke-virtual {p0, v2}, Lcom/canary/app/GuardedForwardActivity;->startActivity(Landroid/content/Intent;)V

    return-void
.end method
