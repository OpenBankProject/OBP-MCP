"""Public /status endpoint for the OBP-MCP server.

Exposes only information that is already public by design (OAuth issuer URLs,
JWKS contents, public OBP API URL, index counts). Never exposes secrets,
tokens, file paths, or internal hostnames.

Serves HTML for browsers and JSON for programmatic clients via content
negotiation (Accept header or ?format=json).
"""

from __future__ import annotations

import html as _html
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

logger = logging.getLogger(__name__)

_START_TIME = time.time()
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


async def _check_http(url: str, timeout: float = 3.0) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            return {"reachable": resp.status_code < 500, "status_code": resp.status_code}
    except Exception as e:
        return {"reachable": False, "status_code": None, "error": str(e)}


async def _jwks_summary(jwks_uri: str, timeout: float = 3.0) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            data = resp.json()
        keys = data.get("keys", [])
        algs = sorted({k.get("alg") for k in keys if k.get("alg")})
        return {"reachable": True, "keys_count": len(keys), "algorithms": algs}
    except Exception as e:
        return {"reachable": False, "keys_count": 0, "error": str(e)}


def _file_mtime_iso(path: Path) -> str | None:
    try:
        if path.exists():
            return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except Exception:
        pass
    return None


async def build_status() -> dict[str, Any]:
    # Deferred imports — the indexes load lazily and we don't want /status
    # to pay that cost on the first hit if it's cold.
    from src.tools.endpoint_index import get_endpoint_index
    from src.tools.glossary_index import get_glossary_index

    obp_base_url = os.getenv("OBP_BASE_URL", "").rstrip("/")
    obp_api_version = os.getenv("OBP_API_VERSION", "")
    auth_enabled = os.getenv("ENABLE_OAUTH", "false").lower() == "true"
    auth_provider = os.getenv("AUTH_PROVIDER", "none") if auth_enabled else "none"

    issuers: list[dict[str, Any]] = []
    if auth_enabled:
        kc = os.getenv("KEYCLOAK_REALM_URL")
        oidc = os.getenv("OBP_OIDC_ISSUER_URL")
        if kc and auth_provider in ("keycloak", "bearer-only"):
            jwks_uri = f"{kc.rstrip('/')}/protocol/openid-connect/certs"
            issuers.append({
                "type": "keycloak",
                "issuer_url": kc,
                "jwks_uri": jwks_uri,
                **(await _jwks_summary(jwks_uri)),
            })
        if oidc and auth_provider in ("obp-oidc", "bearer-only"):
            jwks_uri = f"{oidc.rstrip('/')}/jwks"
            issuers.append({
                "type": "obp-oidc",
                "issuer_url": oidc,
                "jwks_uri": jwks_uri,
                **(await _jwks_summary(jwks_uri)),
            })

    obp_check: dict[str, Any] | None = None
    if obp_base_url:
        root_url = (
            f"{obp_base_url}/obp/{obp_api_version}/root"
            if obp_api_version
            else obp_base_url
        )
        obp_check = {"url": root_url, **(await _check_http(root_url))}

    endpoint_idx = get_endpoint_index()
    glossary_idx = get_glossary_index()
    try:
        endpoints_count = len(getattr(endpoint_idx, "_index", {}))
    except Exception:
        endpoints_count = None
    try:
        tags_count = len(endpoint_idx.get_all_tags())
    except Exception:
        tags_count = None
    try:
        glossary_count = len(glossary_idx)
    except Exception:
        glossary_count = None

    return {
        "server": {
            "name": "OBP-MCP",
            "version": "0.1.0",
            "uptime_seconds": round(time.time() - _START_TIME, 1),
            "base_url": os.getenv("BASE_URL") or None,
        },
        "obp_api": {
            "base_url": obp_base_url or None,
            "api_version": obp_api_version or None,
            "check": obp_check,
        },
        "auth": {
            "enabled": auth_enabled,
            "provider": auth_provider,
            "issuers": issuers,
        },
        "index": {
            "endpoints_count": endpoints_count,
            "tags_count": tags_count,
            "glossary_terms_count": glossary_count,
            "endpoint_index_updated_at": _file_mtime_iso(
                _PROJECT_ROOT / "database" / "endpoint_index.json"
            ),
            "glossary_index_updated_at": _file_mtime_iso(
                _PROJECT_ROOT / "database" / "glossary_index.json"
            ),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _wants_json(request: Request) -> bool:
    if request.query_params.get("format") == "json":
        return True
    accept = request.headers.get("accept", "")
    # Prefer JSON only when the client explicitly asks for it over HTML
    if "application/json" in accept and "text/html" not in accept:
        return True
    return False


def _fmt_uptime(seconds: float) -> str:
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h or d:
        parts.append(f"{h}h")
    if m or h or d:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _render_html(data: dict[str, Any]) -> str:
    esc = _html.escape

    def row(label: str, value: Any) -> str:
        if value is None or value == "":
            rendered = '<span class="muted">—</span>'
        elif isinstance(value, bool):
            cls = "ok" if value else "bad"
            rendered = f'<span class="{cls}">{"yes" if value else "no"}</span>'
        else:
            rendered = esc(str(value))
        return f"<tr><th>{esc(label)}</th><td>{rendered}</td></tr>"

    srv = data["server"]
    obp = data["obp_api"]
    auth = data["auth"]
    idx = data["index"]

    obp_check = obp.get("check") or {}
    obp_rows = "".join([
        row("Base URL", obp.get("base_url")),
        row("API version", obp.get("api_version")),
        row("Probe URL", obp_check.get("url")),
        row("Reachable", obp_check.get("reachable")),
        row("HTTP status", obp_check.get("status_code")),
    ])
    if obp_check.get("error"):
        obp_rows += row("Error", obp_check.get("error"))

    issuer_sections = ""
    for iss in auth.get("issuers", []):
        issuer_sections += f"""
        <section>
          <h3>{esc(iss.get('type', '?'))}</h3>
          <table>
            {row("Issuer URL", iss.get("issuer_url"))}
            {row("JWKS URI", iss.get("jwks_uri"))}
            {row("JWKS reachable", iss.get("reachable"))}
            {row("Keys published", iss.get("keys_count"))}
            {row("Algorithms", ", ".join(iss.get("algorithms") or []) or None)}
            {row("Error", iss.get("error")) if iss.get("error") else ""}
          </table>
        </section>"""
    if not issuer_sections and auth.get("enabled"):
        issuer_sections = '<p class="muted">No issuers configured.</p>'
    if not auth.get("enabled"):
        issuer_sections = '<p class="muted">OAuth is disabled.</p>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>OBP-MCP status</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         max-width: 900px; margin: 2rem auto; padding: 0 1rem; }}
  h1 {{ margin-bottom: 0; }}
  .sub {{ color: #888; font-size: 0.9em; margin-top: 0.25rem; }}
  section {{ margin: 1.5rem 0; padding: 1rem; border: 1px solid #8884; border-radius: 6px; }}
  section h2 {{ margin: 0 0 0.75rem; font-size: 1.1em; }}
  section h3 {{ margin: 1rem 0 0.5rem; font-size: 1em; }}
  table {{ width: 100%; border-collapse: collapse; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }}
  th, td {{ text-align: left; padding: 0.3rem 0.5rem; border-bottom: 1px solid #8882; vertical-align: top; }}
  th {{ width: 35%; font-weight: 500; color: #666; }}
  td {{ word-break: break-all; }}
  .ok {{ color: #2a9d4a; font-weight: 600; }}
  .bad {{ color: #c0392b; font-weight: 600; }}
  .muted {{ color: #888; }}
  footer {{ margin: 2rem 0 1rem; color: #888; font-size: 0.85em; }}
  a {{ color: inherit; }}
</style>
</head>
<body>
  <h1>OBP-MCP status</h1>
  <p class="sub">{esc(srv['name'])} v{esc(srv['version'])} · up {esc(_fmt_uptime(srv['uptime_seconds']))}</p>

  <section>
    <h2>Server</h2>
    <table>
      {row("Name", srv.get("name"))}
      {row("Version", srv.get("version"))}
      {row("Uptime", _fmt_uptime(srv.get("uptime_seconds", 0)))}
      {row("Public base URL", srv.get("base_url"))}
    </table>
  </section>

  <section>
    <h2>OBP API</h2>
    <table>{obp_rows}</table>
  </section>

  <section>
    <h2>Authentication</h2>
    <table>
      {row("OAuth enabled", auth.get("enabled"))}
      {row("Provider", auth.get("provider"))}
    </table>
    {issuer_sections}
  </section>

  <section>
    <h2>Index</h2>
    <table>
      {row("Endpoints", idx.get("endpoints_count"))}
      {row("Tags", idx.get("tags_count"))}
      {row("Glossary terms", idx.get("glossary_terms_count"))}
      {row("Endpoint index updated", idx.get("endpoint_index_updated_at"))}
      {row("Glossary index updated", idx.get("glossary_index_updated_at"))}
    </table>
  </section>

  <footer>
    Generated at {esc(data["timestamp"])} ·
    <a href="?format=json">JSON</a>
  </footer>
</body>
</html>"""


async def health_endpoint(request: Request) -> Response:
    """Liveness probe. Returns 200 as long as the process is serving HTTP.
    Makes no outbound calls and touches no indexes — safe to poll frequently.
    """
    return JSONResponse({"status": "ok"})


async def ready_endpoint(request: Request) -> Response:
    """Readiness probe. Returns 200 if the server is ready to serve traffic:
    indexes have loaded and OBP API is reachable. 503 otherwise.
    """
    from src.tools.endpoint_index import get_endpoint_index
    from src.tools.glossary_index import get_glossary_index

    checks: dict[str, Any] = {}
    ok = True

    try:
        endpoints = len(getattr(get_endpoint_index(), "_index", {}))
        checks["endpoint_index"] = {"ok": endpoints > 0, "count": endpoints}
        if endpoints == 0:
            ok = False
    except Exception as e:
        checks["endpoint_index"] = {"ok": False, "error": str(e)}
        ok = False

    try:
        terms = len(get_glossary_index())
        checks["glossary_index"] = {"ok": terms > 0, "count": terms}
        if terms == 0:
            ok = False
    except Exception as e:
        checks["glossary_index"] = {"ok": False, "error": str(e)}
        ok = False

    obp_base_url = os.getenv("OBP_BASE_URL", "").rstrip("/")
    obp_api_version = os.getenv("OBP_API_VERSION", "")
    if obp_base_url:
        url = (
            f"{obp_base_url}/obp/{obp_api_version}/root"
            if obp_api_version
            else obp_base_url
        )
        result = await _check_http(url, timeout=2.0)
        checks["obp_api"] = {"ok": result.get("reachable", False), **result}
        if not result.get("reachable"):
            ok = False
    else:
        checks["obp_api"] = {"ok": False, "error": "OBP_BASE_URL not set"}
        ok = False

    return JSONResponse(
        {"status": "ok" if ok else "not_ready", "checks": checks},
        status_code=200 if ok else 503,
    )


async def status_endpoint(request: Request) -> Response:
    try:
        data = await build_status()
    except Exception as e:
        logger.exception("Failed to build /status payload")
        if _wants_json(request):
            return JSONResponse({"error": "status_failed", "detail": str(e)}, status_code=500)
        return HTMLResponse(
            f"<h1>status failed</h1><pre>{_html.escape(str(e))}</pre>",
            status_code=500,
        )

    if _wants_json(request):
        return JSONResponse(data)
    return HTMLResponse(_render_html(data))
