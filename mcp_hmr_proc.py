#!/usr/bin/env python
"""Subprocess HMR wrapper for stdio MCP servers.

Watches source files; on change, gracefully restarts the child server
process and emits notifications/*/list_changed so the MCP client refetches
its capability lists.

Why not mcp-hmr (0.0.3.5): mcp-hmr's in-process FastMCP-as-proxy +
ProxyClient stack deadlocks on tools/list when proxying any FastMCP
target via the in-memory transport (live-verified 2026-05-10 with
fastmcp 2.14.7). This wrapper avoids the issue by isolating the server
in a subprocess — child runs the unwrapped MCP server with its own
stdio, wrapper just pipes bytes and forwards line-delimited JSON-RPC.

Usage:
    python mcp_hmr_proc.py <target.py> [--watch <path>]...

Trade-offs:
    - In-flight requests during reload are lost (client should retry).
    - Live RDBG/debug session state in the child is lost on reload.
    - Reload latency = SIGTERM grace (5s max) + spawn + replay init.
"""
# Source: [own] — MCP stdio spec (modelcontextprotocol.io/specification/transports/stdio):
# newline-delimited JSON, one JSON-RPC message per line, UTF-8.
# Source: [own] — asyncio.subprocess stdlib (docs.python.org/3/library/asyncio-subprocess.html).
# Source: watchfiles 1.1.1 — async file watcher (Rust-backed).

import asyncio
import contextlib
import json
import sys
from pathlib import Path
from typing import Optional

import watchfiles


def _log(msg: str) -> None:
    sys.stderr.write(f"[hmr-proc] {msg}\n")
    sys.stderr.flush()


class HmrProc:
    """Subprocess HMR wrapper. One instance per `python mcp_hmr_proc.py` run."""

    def __init__(self, target: Path, watch_paths: list[Path]) -> None:
        self.target = target.resolve()
        self.watch_paths = [p.resolve() for p in watch_paths if p.exists()]
        self.child: Optional[asyncio.subprocess.Process] = None
        self._cached_initialize: Optional[bytes] = None
        self._cached_initialized: Optional[bytes] = None
        # Held during reload — blocks up_pump writes and down_pump reads
        # so the wrapper can replay initialize without races.
        self._reload_lock = asyncio.Lock()
        self._stop = asyncio.Event()

    async def _spawn(self) -> None:
        self.child = await asyncio.create_subprocess_exec(
            sys.executable,
            "-u",  # unbuffered: ensure JSON-RPC lines flush immediately
            str(self.target),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            cwd=str(self.target.parent),
            # stderr inherits from this process by default — child logs reach the user.
        )

    async def _kill_child(self) -> None:
        if self.child is None or self.child.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            self.child.terminate()
        try:
            await asyncio.wait_for(self.child.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                self.child.kill()
            await self.child.wait()

    async def _replay_initialize(self) -> None:
        """Re-run the cached MCP handshake against a fresh child.

        The wrapper-level session is already initialized from the client's
        perspective; the new child must be brought up to that state without
        leaking its own initialize response back to the client.
        """
        if self._cached_initialize is None or self.child is None or self.child.stdin is None:
            return
        self.child.stdin.write(self._cached_initialize)
        await self.child.stdin.drain()
        # Discard child's initialize response — client already has one from the
        # original child. We hold _reload_lock so down_pump won't pick it up.
        if self.child.stdout is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.child.stdout.readline(), timeout=10.0)
        if self._cached_initialized is not None:
            self.child.stdin.write(self._cached_initialized)
            await self.child.stdin.drain()

    async def _emit_list_changed(self) -> None:
        """Tell the client to re-fetch capability lists after reload."""
        for method in (
            "notifications/tools/list_changed",
            "notifications/resources/list_changed",
            "notifications/prompts/list_changed",
        ):
            msg = json.dumps({"jsonrpc": "2.0", "method": method}) + "\n"
            sys.stdout.write(msg)
        sys.stdout.flush()

    async def _cache_handshake(self, line: bytes) -> None:
        """Sniff initialize and notifications/initialized for replay."""
        try:
            msg = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        method = msg.get("method")
        if method == "initialize" and self._cached_initialize is None:
            self._cached_initialize = line
        elif method == "notifications/initialized" and self._cached_initialized is None:
            self._cached_initialized = line

    async def up_pump(self) -> None:
        """stdin (client) -> child.stdin. Caches handshake messages.

        Uses a thread executor for the blocking stdin readline because
        asyncio.connect_read_pipe(sys.stdin) is not supported on Windows
        ProactorEventLoop (the default on Windows).

        On client EOF we close child.stdin (graceful) but do NOT set _stop
        — down_pump must keep draining responses already in flight. The
        run loop tears down once the child exits.
        """
        loop = asyncio.get_running_loop()
        stdin_buf = sys.stdin.buffer
        while not self._stop.is_set():
            line = await loop.run_in_executor(None, stdin_buf.readline)
            if not line:
                # Client closed stdin — pass through to child and let it exit.
                async with self._reload_lock:
                    child = self.child
                    if child is not None and child.stdin is not None and not child.stdin.is_closing():
                        with contextlib.suppress(Exception):
                            child.stdin.close()
                return
            await self._cache_handshake(line)
            async with self._reload_lock:
                child = self.child
                if child is None or child.stdin is None or child.stdin.is_closing():
                    continue  # message dropped; client should retry
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    child.stdin.write(line)
                    await child.stdin.drain()

    async def down_pump(self) -> None:
        """child.stdout -> stdout (client). Survives child respawns.

        Exits only when _stop is set AND the current child has exited.
        EOF on child stdout is treated as "child exited" — if there's a
        new child (mid-reload) we pick it up; otherwise we set _stop.
        """
        while True:
            async with self._reload_lock:
                child = self.child
            if child is None or child.stdout is None:
                if self._stop.is_set():
                    return
                await asyncio.sleep(0.05)
                continue
            try:
                line = await child.stdout.readline()
            except Exception:
                await asyncio.sleep(0.05)
                continue
            if not line:
                # child stdout EOF — child has exited (or is exiting)
                # If client also closed stdin (no new requests coming) we're done.
                # If reload is in progress, _reload_lock will block briefly and
                # we'll pick up the fresh child on the next iteration.
                if child.returncode is not None and not self._reload_lock.locked():
                    self._stop.set()
                    return
                await asyncio.sleep(0.05)
                continue
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def watcher(self) -> None:
        """File watcher: on any change in watch_paths, reload the child."""
        if not self.watch_paths:
            return
        watch = [str(p) for p in self.watch_paths]
        try:
            async for _changes in watchfiles.awatch(*watch, stop_event=self._stop):
                if self._stop.is_set():
                    return
                await self._reload()
        except RuntimeError:
            # watchfiles raises when stop_event triggers mid-iteration; benign
            return

    async def _reload(self) -> None:
        async with self._reload_lock:
            _log("source change → reloading child")
            await self._kill_child()
            await self._spawn()
            await self._replay_initialize()
        await self._emit_list_changed()
        _log("child reloaded")

    async def run(self) -> None:
        await self._spawn()
        try:
            await asyncio.gather(
                self.up_pump(),
                self.down_pump(),
                self.watcher(),
            )
        finally:
            await self._kill_child()


def _parse_args(argv: list[str]) -> tuple[Path, list[Path]]:
    if not argv:
        sys.stderr.write("usage: python mcp_hmr_proc.py <target.py> [--watch <path>]...\n")
        sys.exit(2)
    target = Path(argv[0])
    if not target.is_file():
        sys.stderr.write(f"[hmr-proc] target not found: {target}\n")
        sys.exit(2)
    watch_paths: list[Path] = [target]
    i = 1
    while i < len(argv):
        if argv[i] == "--watch" and i + 1 < len(argv):
            watch_paths.append(Path(argv[i + 1]))
            i += 2
        else:
            i += 1
    return target, watch_paths


def main() -> None:
    target, watch_paths = _parse_args(sys.argv[1:])
    proc = HmrProc(target, watch_paths)
    _log(f"target: {proc.target}")
    _log(f"watching: {[str(p) for p in proc.watch_paths]}")
    try:
        asyncio.run(proc.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
