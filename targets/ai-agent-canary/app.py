"""A small local assistant service with a vault and a deferred export queue.

JSON on stdin is the service's public interface. The worker entry is a
separate, operator-triggered process. State is persisted in /work/state.
"""
import hmac
import json
import sys
from pathlib import Path

STATE = Path("/work/state")


def authorized(request):
    return hmac.compare_digest(str(request.get("token", "")), (STATE / "owner-token").read_text())


def dispatch(request, worker=False):
    operation = request.get("operation")
    if operation == "public.info":
        return {"ok": True, "content": "Public service information"}
    if operation == "vault.read":
        return {"ok": True, "content": (STATE / "vault").read_text()}
    if operation == "export.enqueue":
        job = {"action": request.get("action", "summary")}
        (STATE / "pending.json").write_text(json.dumps(job))
        return {"ok": True, "content": "queued"}
    if operation == "export.run" and worker:
        path = STATE / "pending.json"
        if not path.exists():
            return {"ok": True, "content": "no pending export"}
        job = json.loads(path.read_text())
        path.unlink()
        content = (STATE / "vault").read_text() if job["action"] == "vault" else "public summary"
        return {"ok": True, "content": content}
    return {"ok": False, "content": "unsupported operation"}


if __name__ == "__main__":
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        response = dispatch(request, worker="--worker" in sys.argv[1:])
        print(json.dumps(response))
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"ok": False, "content": str(exc)}))
        sys.exit(1)
