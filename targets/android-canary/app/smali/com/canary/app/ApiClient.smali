.class public Lcom/canary/app/ApiClient;
.super Ljava/lang/Object;
.source "ApiClient.java"

# The app's REST client (backed by OkHttp). The base URL and a legacy cleartext
# "ping" endpoint are INTELLIGENCE about the server surface — not a vulnerability
# in themselves, but the discovery vector server-side testing (EASM/DAST) starts
# from. harvest() lifts them into intel.json (endpoints + hosts).

.field private static final BASE_URL:Ljava/lang/String; = "https://api.canary.example/v1/sync"

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

# A legacy health check over plaintext HTTP — surfaces as a cleartext endpoint.
.method public ping()V
    .locals 2
    const-string v0, "http://legacy.canary.example/ping"
    new-instance v1, Lokhttp3/OkHttpClient;
    invoke-direct {v1}, Lokhttp3/OkHttpClient;-><init>()V
    return-void
.end method
