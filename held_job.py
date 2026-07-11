"""B1 (roadmap 260708, ADR-049): persistent JOB-контекст helper.

Генерирует BSL для запуска/освобождения долгоживущего debug-worker'а
`mcp_ОтладкаВыполненияКода.ВыполнитьКодСУдержанием` (расширение MCP_Сервер) и
опционально исполняет его напрямую через HTTP execute_code (Ф-1(a) transport),
если в env заданы креды MCP_ONEC_* (как у 1c-mcp-crud). Без кредов — двухфазный
режим (Ф-1(b)): tool возвращает готовый BSL, агент запускает его через 1c-mcp-crud.

Standalone (imports только stdlib + httpx, как logpoints/coverage) — не импортирует
mcp_debug_server (нет циклов).
"""

from __future__ import annotations

import json
import logging
import os

log = logging.getLogger("1c-debug-mcp.held-job")

WORKER_METHOD = "mcp_ОтладкаВыполненияКода.ВыполнитьКодСУдержанием"
RELEASE_STORAGE = "mcp_debug_hold_release"  # ХранилищеОбщихНастроек object name
DEFAULT_TIMEOUT_SEC = 60


def _bsl_string(s: str) -> str:
    """Wrap a Python string as a BSL string literal.

    Two BSL rules: (1) an inner `"` is doubled `""`; (2) a string literal CANNOT
    contain a raw newline — each continuation physical line must start with `|`
    (the pipe is a marker; the value still contains the newline). Without (2) a
    multi-line `code` (the common debug case) produced INVALID BSL that broke at
    the first newline (adversarial review 260711).
    """
    s = (s or "").replace('"', '""')
    s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\n|")
    return '"' + s + '"'


def build_trigger_code(code: str, key: str, timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> str:
    """BSL that spawns the held-worker as a background job.

    Спавнит НОВЫЙ rphost (его ловит debug_arm_next_rphost / Шаблон 6), исполняет
    `code` (BP внутри fire'ит) и держит контекст до release-флага или таймаута.
    """
    return (
        "П = Новый Массив;\n"
        f"П.Добавить({_bsl_string(code)});\n"
        f"П.Добавить({_bsl_string(key)});\n"
        f"П.Добавить({int(timeout_sec)});\n"
        f'ФоновыеЗадания.Выполнить("{WORKER_METHOD}", П);'
    )


def build_release_code(key: str) -> str:
    """BSL that releases a held worker (sets the release flag it polls)."""
    return f"ХранилищеОбщихНастроек.Сохранить({_bsl_string(RELEASE_STORAGE)}, {_bsl_string(key)}, Истина);"


def make_key(session_id: str, seq: int) -> str:
    """Deterministic hold key (no Math.random in this env). session-scoped + seq."""
    return f"hold-{(session_id or 'sess')[:8]}-{seq}"


# ---------------------------------------------------------------------------
# Optional Ф-1(a) transport: run execute_code directly over the extension HTTP
# service (same endpoint 1c-mcp-crud uses). Enabled only when MCP_ONEC_* env set.
# ---------------------------------------------------------------------------

def transport_available() -> bool:
    return bool(os.environ.get("MCP_ONEC_URL"))


def _service_root() -> str:
    return os.environ.get("MCP_ONEC_SERVICE_ROOT", "mcp")


async def execute_code_http(http, code: str) -> dict:
    """POST execute_code to <MCP_ONEC_URL>/hs/<root>/rpc (JSON-RPC tools/call).

    `http` is an httpx.AsyncClient (reused from the wrapper). Basic-auth from env.
    Returns {ok, raw|error}. Never raises — B1 trigger/release is best-effort.
    """
    base = os.environ.get("MCP_ONEC_URL", "").rstrip("/")
    if not base:
        return {"ok": False, "error": "no MCP_ONEC_URL"}
    url = f"{base}/hs/{_service_root()}/rpc"
    user = os.environ.get("MCP_ONEC_USERNAME", "")
    pwd = os.environ.get("MCP_ONEC_PASSWORD", "")
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "execute_code", "arguments": {"code": code}},
    }
    try:
        import httpx

        auth = httpx.BasicAuth(user, pwd) if user else None
        resp = await http.post(url, json=payload, auth=auth, timeout=15.0)
        if resp.status_code >= 400:
            return {"ok": False, "error": f"HTTP {resp.status_code}: {(resp.text or '')[:300]}"}
        try:
            return {"ok": True, "raw": resp.json()}
        except (ValueError, json.JSONDecodeError):
            return {"ok": True, "raw": (resp.text or "")[:300]}
    except Exception as e:  # network/transport — best-effort
        log.debug("held-job execute_code_http failed: %s", e)
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
