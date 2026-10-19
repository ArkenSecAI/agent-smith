#!/usr/bin/python3
"""One real installed Kali API + MCP stdio bridge per supervised run.

Compatibility contract (Main must reconcile with the image's exact packages):
* Kali mcp-kali-server 0.0~git20260317.00154c0 command interface:
  kali-server-mcp --ip 127.0.0.1 --port N; mcp-server --server URL --timeout S.
* Kali hexstrike-ai 0.0~git20260803.d689933 command interface:
  hexstrike_server --port N; hexstrike_mcp --server URL --timeout S.
  Kali's loopback-binding patch is REQUIRED. Upstream's 0.0.0.0 binding is
  rejected by checking the actual listening socket, before any tool call.
* Debian python3-mcp exposes the v1 ClientSession, StdioServerParameters,
  stdio_client, and Pydantic v2 model_dump(mode='json', by_alias=True) APIs.

Primary command documentation: https://www.kali.org/tools/mcp-kali-server/
and https://www.kali.org/tools/hexstrike-ai/ . No version is guessed at runtime:
dpkg-query versions and hashes of installed package sources are recorded.
No model client, agent loop, package acquisition, or tool reimplementation.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Keep SDK imports here at module scope. Pure result/provenance helpers remain
# importable by stdlib-only regression tests when python3-mcp is not installed.
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.shared.exceptions import McpError
except ImportError:
    ClientSession = StdioServerParameters = stdio_client = None
    McpError = None

# Python -I does not put this directory on sys.path, so keep this program
# independently installable next to supervisor.py without importing it.
MAX_REQUEST = 1024 * 1024
MAX_RESULT = 16 * 1024 * 1024
PACKAGES = {
    'kali': ('mcp-kali-server', '/usr/bin/kali-server-mcp', '/usr/bin/mcp-server'),
    'hexstrike': ('hexstrike-ai', '/usr/bin/hexstrike_server', '/usr/bin/hexstrike_mcp'),
}


def encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('ascii')


def commit_result(path: Path, value: dict) -> None:
    data = encode(value)
    if len(data) > MAX_RESULT:
        # Do not truncate original metadata and pretend it is a complete result.
        raise ValueError('MCP result exceeds durable metadata limit')
    temporary = path.with_name(path.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def emit(event: dict) -> None:
    # Output is an original, combined byte log. Large metadata travels through
    # supervisor read() chunks; it is never a large control-channel frame.
    sys.stdout.buffer.write(encode(event) + b'\n')
    sys.stdout.buffer.flush()


def package_pin(package: str) -> dict:
    info = subprocess.run(
        ['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${Status}', package],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True, timeout=10, text=True,
    ).stdout.split('\t')
    if len(info) != 4 or info[3] != 'install ok installed':
        raise RuntimeError('required package is not installed')
    listing = subprocess.run(
        ['/usr/bin/dpkg-query', '-L', package], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10, text=True,
    ).stdout.splitlines()
    files = []
    for name in sorted(set(listing)):
        path = Path(name)
        # Hash installed code and wrappers, including Debian's local patches;
        # avoid recursively discovering unrelated or user files.
        if not path.is_absolute() or not (path.suffix in ('.py', '.sh') or path.parent == Path('/usr/bin')):
            continue
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        files.append({'path': str(path), 'sha256': digest.hexdigest()})
    if not files:
        raise RuntimeError('installed package source hashes unavailable')
    return dict(package=info[0], version=info[1], architecture=info[2], sources=files)


def result_facts(result: object) -> dict:
    """Interpret explicit status fields without modifying the upstream object.

    Both installed bridges can wrap an API dictionary in TextContent JSON.
    Inspect status-bearing objects and their result/data wrappers, not arbitrary
    scan stdout text. A timeout flag always wins over upstream success=true.
    """
    facts = {'timedOut': False, 'failed': False, 'cache': []}
    pending: list[tuple[object, str, int]] = [(result, '$', 0)]
    while pending:
        value, location, depth = pending.pop()
        if depth > 20 or not isinstance(value, dict):
            continue
        if any(value.get(key) is True for key in ('timed_out', 'timedOut', 'timeout')):
            facts['timedOut'] = True
        if value.get('status') in ('timeout', 'timed_out', 'timedOut'):
            facts['timedOut'] = True
        if value.get('isError') is True or value.get('success') is False or value.get('error'):
            facts['failed'] = True
        for key in ('return_code', 'exit_code', 'exitCode'):
            if type(value.get(key)) is int and value[key] != 0:
                facts['failed'] = True
        # Explicit error messages also cover the bridges' requests timeout
        # mapping, which may omit a Boolean timed_out field entirely.
        error = value.get('error')
        if isinstance(error, str) and any(word in error.lower() for word in ('timed out', 'timeout')):
            facts['timedOut'] = True
        for key in ('cached', 'cache_hit', 'cacheHit', 'cache', 'from_cache'):
            if key in value:
                facts['cache'].append({'path': location + '.' + key, 'value': value[key]})
        for key in ('structuredContent', 'result', 'data', '_meta'):
            if key in value:
                pending.append((value[key], location + '.' + key, depth + 1))
        content = value.get('content')
        if isinstance(content, list):
            for index, block in enumerate(content):
                if isinstance(block, dict) and block.get('type') == 'text' and isinstance(block.get('text'), str):
                    try:
                        parsed = json.loads(block['text'])
                    except (ValueError, RecursionError):
                        continue
                    pending.append((parsed, f'{location}.content[{index}].text', depth + 1))
    return facts


def result_outcome(result: dict) -> tuple[str, int, dict]:
    facts = result_facts(result)
    if facts['timedOut']:
        return 'timed_out', 124, facts
    if facts['failed']:
        return 'error', 1, facts
    return 'completed', 0, facts


def exception_metadata(error: BaseException) -> dict:
    value: dict = {'type': type(error).__name__, 'message': str(error)}
    if McpError is not None and isinstance(error, McpError):
        value['mcpError'] = error.error.model_dump(mode='json', by_alias=True, exclude_none=False)
    if isinstance(error, BaseExceptionGroup):
        value['exceptions'] = [exception_metadata(child) for child in error.exceptions]
    return value


def exception_timed_out(error: BaseException) -> bool:
    if isinstance(error, TimeoutError):
        return True
    if isinstance(error, BaseExceptionGroup):
        return any(exception_timed_out(child) for child in error.exceptions)
    if McpError is not None and isinstance(error, McpError):
        return any(word in error.error.message.lower() for word in ('timed out', 'timeout'))
    return False


def check_listener(port: int, api_pid: int) -> bool:
    """Require an API-owned IPv4 loopback socket, not an unrelated service.

    The installed wrapper must exec its API or leave a descendant in this run's
    cgroup. Matching cgroup ownership also handles Debian shell/sudo wrappers.
    """
    rows = Path('/proc/net/tcp').read_text().splitlines()[1:]
    listeners = []
    for row in rows:
        columns = row.split()
        address, port_hex = columns[1].split(':')
        if columns[3] == '0A' and int(port_hex, 16) == port:
            if address != '0100007F':
                raise RuntimeError('installed API is not bound exclusively to IPv4 loopback')
            listeners.append(columns[9])
    for row in Path('/proc/net/tcp6').read_text().splitlines()[1:]:
        columns = row.split()
        if columns[3] == '0A' and int(columns[1].split(':')[1], 16) == port:
            raise RuntimeError('unexpected IPv6 API listener')
    if not listeners:
        return False
    # Descendants may have daemonized into new sessions; cgroup membership is
    # inherited regardless of session/process-group behavior.
    own_group = Path('/proc/self/cgroup').read_text()
    candidates = [Path('/proc') / str(api_pid)]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or entry in candidates:
            continue
        try:
            if (entry / 'cgroup').read_text() == own_group:
                candidates.append(entry)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    for candidate in candidates:
        try:
            for fd in (candidate / 'fd').iterdir():
                try:
                    if os.readlink(fd) in {f'socket:[{inode}]' for inode in listeners}:
                        return True
                except FileNotFoundError:
                    continue
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    raise RuntimeError('API listener is not owned by the supervised run')


def check_api_health(port: int, timeout: float) -> None:
    # No ambient proxy variables, redirects, credentials, or remote URLs.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    url = f'http://127.0.0.1:{port}/health'
    with opener.open(url, timeout=timeout) as reply:
        data = reply.read(MAX_REQUEST + 1)
        if len(data) > MAX_REQUEST:
            raise RuntimeError('API health response exceeds limit')
        if reply.status != 200 or not isinstance(json.loads(data), dict):
            raise RuntimeError('invalid API health response')


async def wait_api(api: asyncio.subprocess.Process, port: int, deadline: float) -> None:
    while time.monotonic() < deadline:
        if api.returncode is not None:
            raise RuntimeError('installed API exited before readiness')
        if check_listener(port, api.pid):
            # HexStrike /health enumerates tools and samples CPU for one second.
            # Abandoning it every 250 ms created overlapping discovery requests
            # whose HTTP 200 replies always arrived after the caller timed out.
            # Keep one request in flight within the existing readiness deadline;
            # HTTP/protocol errors must surface, not turn into retry timeouts.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(asyncio.to_thread(check_api_health, port, remaining), remaining)
            except TimeoutError as error:
                raise TimeoutError('installed API readiness timed out') from error
            except urllib.error.URLError as error:
                if isinstance(error.reason, TimeoutError):
                    raise TimeoutError('installed API readiness timed out') from error
                raise
            return
        await asyncio.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise TimeoutError('installed API readiness timed out')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('API health redirect rejected')


def prepare_call(request: dict, tools: list[dict]) -> tuple[dict, dict]:
    selected = next((tool for tool in tools if tool.get('name') == request['tool']), None)
    if selected is None:
        raise ValueError('requested tool is not provided by the installed bridge')
    # Only the direct nmap tool is used for HexStrike execution. This prevents
    # invoking its separate autonomous/agent/recovery APIs. tools/list still
    # returns the unmodified real catalogue, including unsupported tool names.
    if request['server'] == 'hexstrike' and request['tool'] != 'nmap_scan':
        raise ValueError('HexStrike execution is restricted to direct nmap_scan; no second agent loop')
    arguments = dict(request.get('arguments', {}))
    properties = selected.get('inputSchema', {}).get('properties', {})
    disabled = []
    for name in ('use_cache', 'cache_enabled'):
        if isinstance(properties.get(name), dict) and properties[name].get('type') == 'boolean':
            arguments[name] = False
            disabled.append(name)
    cache = {
        'policy': 'disabled-by-tool-argument' if disabled else 'upstream-default-unverified',
        'disabledArguments': disabled,
        'freshApiPerRun': True,
        'note': 'No cache-hit or fresh-execution claim is inferred from a successful MCP response.',
    }
    return arguments, cache


async def run(request: dict, result_path: Path) -> int:
    envelope: dict = {'schema': 1, 'server': request.get('server'), 'kind': request.get('kind'),
                      'tool': request.get('tool'), 'outcome': 'unknown'}
    api: asyncio.subprocess.Process | None = None
    exit_code = 1
    try:
        if ClientSession is None:
            raise RuntimeError('python3-mcp with the supported v1 API is required')
        package, api_command, bridge_command = PACKAGES[request['server']]
        if not all(os.access(command, os.X_OK) for command in (api_command, bridge_command)):
            raise RuntimeError('required installed API/stdio commands are unavailable')
        envelope['pins'] = [package_pin(package), package_pin('python3-mcp')]
        if request.get('tool') == 'nmap_scan':
            envelope['pins'].append(package_pin('nmap'))
        envelope['sdkVersion'] = importlib.metadata.version('mcp')
        emit({'event': 'mcp-provenance', 'server': request['server'], 'pins': envelope['pins'],
              'sdkVersion': envelope['sdkVersion']})
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        # No configurable API URL or command. A port collision is an explicit
        # failed run, never permission to attach to an existing service.
        api_args = [api_command, '--port', str(port)]
        if request['server'] == 'kali':
            api_args += ['--ip', '127.0.0.1']
        env = {key: value for key, value in os.environ.items()
               if key in ('PATH', 'HOME', 'LANG', 'TERM', 'PYTHONUNBUFFERED')}
        env.update(DEBUG_MODE='0', PYTHONUNBUFFERED='1')
        api = await asyncio.create_subprocess_exec(*api_args, stdin=asyncio.subprocess.DEVNULL,
                                                   stdout=sys.stderr, stderr=sys.stderr, env=env)
        timeout_seconds = request['timeoutMs'] / 1000
        await wait_api(api, port, time.monotonic() + min(30, timeout_seconds))
        params = StdioServerParameters(command=bridge_command,
                                       args=['--server', f'http://127.0.0.1:{port}',
                                             '--timeout', str(max(1, math.ceil(timeout_seconds)))],
                                       env=env, cwd=request['cwd'])
        # The supervisor deadline is authoritative and kills this whole cgroup.
        # This SDK timeout additionally produces a structured result when time
        # remains to drain; an SDK subprocess session is still in the run cgroup.
        async with stdio_client(params, errlog=sys.stderr) as (reader, writer):
            async with ClientSession(reader, writer,
                                     read_timeout_seconds=datetime.timedelta(seconds=timeout_seconds)) as session:
                initialized = await session.initialize()
                envelope['initialize'] = initialized.model_dump(mode='json', by_alias=True, exclude_none=False)
                pages = []
                tools = []
                cursor = None
                seen = set()
                for _ in range(128):
                    page = await session.list_tools(cursor=cursor)
                    raw = page.model_dump(mode='json', by_alias=True, exclude_none=False)
                    pages.append(raw)
                    tools.extend(raw['tools'])
                    cursor = raw.get('nextCursor')
                    if cursor is None:
                        break
                    if cursor in seen:
                        raise RuntimeError('installed MCP returned a repeated tools cursor')
                    seen.add(cursor)
                else:
                    raise RuntimeError('installed MCP catalogue exceeds pagination bound')
                if request['kind'] == 'mcp-list':
                    envelope['result'] = pages[0] if len(pages) == 1 else {'pages': pages}
                    envelope['outcome'] = 'completed'
                    exit_code = 0
                else:
                    arguments, cache = prepare_call(request, tools)
                    envelope['cacheProvenance'] = cache
                    envelope['effectiveArguments'] = arguments
                    result = await session.call_tool(request['tool'], arguments)
                    raw = result.model_dump(mode='json', by_alias=True, exclude_none=False)
                    envelope['result'] = raw
                    outcome, exit_code, facts = result_outcome(raw)
                    envelope['outcome'] = outcome
                    envelope['observedFacts'] = facts
                # Commit before the SDK tears down the bridge. A stalled bridge
                # cleanup must not erase a tool result already received.
                emit({'event': 'mcp-result', 'envelope': envelope})
                commit_result(result_path, envelope)
        if api.returncode is not None:
            envelope['apiExitCode'] = api.returncode
            if envelope.get('outcome') != 'timed_out':
                envelope['outcome'] = 'error'
                exit_code = 1
    except Exception as error:
        envelope['error'] = exception_metadata(error)
        if exception_timed_out(error) or envelope.get('observedFacts', {}).get('timedOut'):
            envelope['outcome'] = 'timed_out'
            exit_code = 124
        else:
            envelope['outcome'] = 'error'
            exit_code = 1
        # Preserve any already-received result alongside transport/cleanup errors.
    finally:
        # Native descendants are stopped by the supervisor's cgroup.kill, also
        # when the stdio SDK uses setsid or an API command double-forks.
        if api is not None and api.returncode is None:
            try:
                api.terminate()
                await asyncio.wait_for(api.wait(), 2)
            except ProcessLookupError:
                pass
            except asyncio.TimeoutError:
                try:
                    api.kill()
                    await asyncio.wait_for(api.wait(), 2)
                except ProcessLookupError:
                    pass
                except asyncio.TimeoutError as error:
                    envelope['cleanupError'] = exception_metadata(error)
                    if envelope.get('outcome') != 'timed_out':
                        envelope['outcome'] = 'error'
                        exit_code = 1
        emit({'event': 'mcp-result', 'envelope': envelope})
        commit_result(result_path, envelope)
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description='Supervised installed MCP request runner')
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.request.open('rb') as stream:
            data = stream.read(MAX_REQUEST + 1)
        if len(data) > MAX_REQUEST:
            raise ValueError('request limit exceeded')
        request = json.loads(data)
        if request.get('kind') not in ('mcp', 'mcp-list') or request.get('server') not in PACKAGES:
            raise ValueError('invalid runner request')
        return asyncio.run(run(request, args.result))
    except Exception as error:
        print('MCP runner failed: ' + type(error).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
