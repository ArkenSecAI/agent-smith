#!/usr/bin/python3
"""Agent Smith guest control. Python 3.11+, Linux cgroup v2 with cgroup.kill.

Import seam: await Supervisor.open(config, store, work, boundaries=...). The
injected BoundaryFactory is solely for owned local fixtures; main() always uses
CgroupV2Factory and never accepts a switch to weaken containment.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import copy
import datetime
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import stat
import struct
import sys
import termios
import time
from typing import Protocol
import uuid


MAX_FRAME = 1024 * 1024
MAX_CHUNK = 64 * 1024
MAX_SNAPSHOT_RESULT = 16 * 1024
MAX_RUNS = 512
MAX_ACTIVE = 16
MAX_OUTPUT = 256 * 1024 * 1024
MAX_MCP_RESULT = 16 * 1024 * 1024
FW_CONFIG = Path('/sys/firmware/qemu_fw_cfg/by_name/opt/agent-smith/config/raw')
CHANNEL = Path('/dev/virtio-ports/org.arkensec.smith')
STORE = Path('/var/lib/agent-smith/runs')
WORK = Path('/work')


class ControlError(Exception):
    """Safe, token-free error that may be returned over the control channel."""


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def reject_constant(value: str) -> None:
    raise ValueError('non-finite JSON number')


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def decode(data: bytes) -> object:
    return json.loads(data, parse_constant=reject_constant, object_pairs_hook=unique_object)


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path: Path, value: object) -> None:
    temp = path.with_name(path.name + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encode(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        fsync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def read_json(path: Path, limit: int = MAX_FRAME) -> object:
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ControlError('stored document exceeds limit')
    return decode(data)


def identifier(value: object) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise ControlError('expected canonical UUID')
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise ControlError('expected canonical UUID') from None
    return value


def integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ControlError('integer outside allowed range')
    return value


def validate_config(config: object) -> dict:
    if not isinstance(config, dict) or set(config) != {'project', 'generation', 'token'}:
        raise ControlError('invalid boot configuration')
    identifier(config['project'])
    identifier(config['generation'])
    token = config['token']
    if not isinstance(token, str) or not 32 <= len(token) <= 1024 or not token.isascii():
        raise ControlError('invalid boot authentication material')
    return dict(config)


class Boundary(Protocol):
    def attach(self, pid: int) -> None: ...
    def kill(self) -> None: ...
    def empty(self) -> bool: ...
    def remove(self) -> None: ...


class BoundaryFactory(Protocol):
    def create(self, run_id: str) -> Boundary: ...
    def recover(self, run_id: str) -> Boundary | None: ...


class CgroupV2:
    def __init__(self, path: Path):
        self.path = path

    def attach(self, pid: int) -> None:
        (self.path / 'cgroup.procs').write_text(str(pid), encoding='ascii')
        if str(pid) not in (self.path / 'cgroup.procs').read_text().split():
            raise ControlError('failed to establish run cgroup')

    def kill(self) -> None:
        (self.path / 'cgroup.kill').write_text('1', encoding='ascii')

    def empty(self) -> bool:
        events = dict(line.split() for line in (self.path / 'cgroup.events').read_text().splitlines())
        return events.get('populated') == '0'

    def remove(self) -> None:
        # A descendant may create nested cgroups; cgroup.kill covers those too.
        for base, dirs, _ in os.walk(self.path, topdown=False):
            for name in dirs:
                Path(base, name).rmdir()
        self.path.rmdir()


class CgroupV2Factory:
    def __init__(self):
        mount = Path('/sys/fs/cgroup')
        if not (mount / 'cgroup.controllers').is_file():
            raise ControlError('cgroup v2 is required')
        entries = Path('/proc/self/cgroup').read_text().splitlines()
        unified = [line[3:] for line in entries if line.startswith('0::/')]
        if len(unified) != 1 or unified[0] == '/':
            raise ControlError('a delegated service cgroup is required')
        service = mount / unified[0].lstrip('/')
        self.root = service / 'runs'
        self.root.mkdir(exist_ok=True)
        probe = self.root / ('probe-' + str(uuid.uuid4()))
        probe.mkdir()
        try:
            # Actually open/write the safety primitive, rather than infer it
            # from kernel version or from the presence of a configuration file.
            (probe / 'cgroup.kill').write_text('1', encoding='ascii')
        finally:
            probe.rmdir()

    def create(self, run_id: str) -> CgroupV2:
        path = self.root / identifier(run_id)
        path.mkdir()
        return CgroupV2(path)

    def recover(self, run_id: str) -> CgroupV2 | None:
        path = self.root / identifier(run_id)
        return CgroupV2(path) if path.is_dir() else None


class Frames:
    """Incremental JSONL framing with bounded memory and discard-to-newline.

    None denotes one oversized frame. A disconnect discards any partial frame;
    it is never joined to the next connection's bytes.
    """

    def __init__(self):
        self.pending = bytearray()
        self.discarding = False

    def feed(self, data: bytes) -> list[bytes | None]:
        result = []
        # Iterate newline spans, not bytes. Callers read at most MAX_CHUNK.
        parts = data.split(b'\n')
        for index, part in enumerate(parts):
            complete = index < len(parts) - 1
            if not self.discarding:
                if len(self.pending) + len(part) > MAX_FRAME:
                    self.pending.clear()
                    self.discarding = True
                else:
                    self.pending.extend(part)
            if complete:
                result.append(None if self.discarding else bytes(self.pending))
                self.pending.clear()
                self.discarding = False
        return result


async def fd_ready(fd: int, write: bool = False) -> None:
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def ready() -> None:
        if not future.done():
            future.set_result(None)

    register = loop.add_writer if write else loop.add_reader
    remove = loop.remove_writer if write else loop.remove_reader
    register(fd, ready)
    try:
        await future
    finally:
        remove(fd)


async def write_fd(fd: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        try:
            count = os.write(fd, remaining)
        except BlockingIOError:
            await fd_ready(fd, write=True)
            continue
        if count == 0:
            raise OSError(errno.EPIPE, 'closed channel')
        remaining = remaining[count:]


class Run:
    def __init__(self, directory: Path, record: dict):
        self.directory = directory
        self.record = record
        self.process: asyncio.subprocess.Process | None = None
        self.boundary: Boundary | None = None
        self.output_fd: int | None = None
        self.input_fd: int | None = None
        self.pty_fd: int | None = None
        self.task: asyncio.Task | None = None
        self.readers: list[asyncio.Task] = []
        self.reason: str | None = None
        self.capture_failed = False
        self.io_lock = asyncio.Lock()

    @property
    def snapshot(self) -> dict:
        return self.record['snapshot']

    def save(self) -> None:
        atomic_json(self.directory / 'state.json', self.record)

    def append(self, data: bytes) -> None:
        if self.output_fd is None:
            raise ControlError('output store is closed')
        remaining = MAX_OUTPUT - self.snapshot['outputBytes']
        chunk = data[:remaining]
        view = memoryview(chunk)
        while view:
            count = os.write(self.output_fd, view)
            view = view[count:]
        os.fsync(self.output_fd)
        self.snapshot['outputBytes'] += len(chunk)
        if len(chunk) != len(data):
            self.capture_failed = True
            self.reason = 'unknown'
            self.record['failure'] = 'output quota exceeded; capture incomplete'
        self.save()


class Supervisor:
    def __init__(self, config: dict, store: Path, work: Path, boundaries: BoundaryFactory):
        self.config = validate_config(config)
        self.store = store.resolve()
        self.work = work.resolve(strict=True)
        self.boundaries = boundaries
        self.runs: dict[str, Run] = {}
        self.lock_fd: int | None = None
        self.closed = False
        self.mutation_lock = asyncio.Lock()

    @classmethod
    async def open(cls, config: dict, store: Path, work: Path,
                   *, boundaries: BoundaryFactory | None = None) -> Supervisor:
        instance = cls(config, store, work,
                       boundaries if boundaries is not None else CgroupV2Factory())
        instance.store.mkdir(parents=True, exist_ok=True, mode=0o700)
        mode = instance.store.stat()
        if mode.st_uid != os.geteuid() or stat.S_IMODE(mode.st_mode) & 0o077:
            raise ControlError('run store must be owned and mode 0700')
        instance.lock_fd = os.open(instance.store / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(instance.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            await instance.recover()
        except BaseException:
            os.close(instance.lock_fd)
            instance.lock_fd = None
            raise
        return instance

    async def recover(self) -> None:
        for directory in sorted(self.store.iterdir()):
            if directory.name.startswith('.'):
                continue
            identifier(directory.name)
            if directory.is_symlink() or not directory.is_dir():
                raise ControlError('invalid run store entry')
            state = directory / 'state.json'
            if not state.exists():
                # No exec gate can have opened before the first durable state.
                # Retain this interrupted allocation; never reuse its UUID.
                continue
            record = read_json(state, MAX_FRAME + MAX_SNAPSHOT_RESULT + 16384)
            if not isinstance(record, dict) or record.get('schema') != 1:
                raise ControlError('invalid run state')
            run = Run(directory, record)
            snapshot = run.snapshot
            if snapshot['id'] != directory.name or snapshot['project'] != self.config['project']:
                raise ControlError('run store belongs to a different project')
            snapshot['outputBytes'] = (directory / 'output.bin').stat().st_size
            boundary = self.boundaries.recover(directory.name)
            survivors = False
            if boundary is not None:
                survivors = not boundary.empty()
                boundary.kill()
                deadline = time.monotonic() + 5
                while not boundary.empty():
                    if time.monotonic() > deadline:
                        raise ControlError('historical descendants could not be stopped')
                    await asyncio.sleep(0.02)
                boundary.remove()
            if survivors or snapshot['state'] == 'running' or not snapshot['captureComplete']:
                snapshot.update(state='unknown', captureComplete=False, endedAt=now())
                record['failure'] = 'supervisor restarted; native outcome or final drain was not observed'
            run.save()
            self.runs[directory.name] = run

    def get(self, run_id: object) -> Run:
        run = self.runs.get(identifier(run_id))
        if run is None:
            raise ControlError('unknown run')
        return run

    def current(self, run: Run, *, active: bool = True) -> None:
        if run.snapshot['generation'] != self.config['generation']:
            raise ControlError('stale run generation')
        if active and (run.snapshot['state'] != 'running' or run.process is None
                       or run.process.returncode is not None or run.reason is not None):
            raise ControlError('run is not accepting input')

    def validate_request(self, request: object) -> dict:
        if not isinstance(request, dict):
            raise ControlError('invalid run request')
        request = copy.deepcopy(request)
        allowed = {'actor', 'kind', 'argv', 'cwd', 'pty', 'server', 'tool', 'arguments', 'timeoutMs'}
        if set(request) - allowed:
            raise ControlError('unsupported run field')
        if request.get('actor') not in ('human', 'agent'):
            raise ControlError('invalid actor')
        if request.get('kind') not in ('command', 'mcp', 'mcp-list'):
            raise ControlError('invalid run kind')
        integer(request.get('timeoutMs'), 1, 24 * 60 * 60 * 1000)
        cwd = request.get('cwd', str(self.work))
        if not isinstance(cwd, str) or '\0' in cwd:
            raise ControlError('invalid working directory')
        directory = Path(cwd)
        if not directory.is_absolute():
            directory = self.work / directory
        try:
            directory = directory.resolve(strict=True)
        except OSError:
            raise ControlError('working directory does not exist') from None
        if not directory.is_relative_to(self.work) or not directory.is_dir():
            raise ControlError('working directory must be under the work root')
        request['cwd'] = str(directory)
        if request['kind'] == 'command':
            argv = request.get('argv')
            if not isinstance(argv, list) or not 1 <= len(argv) <= 256:
                raise ControlError('invalid argv')
            if any(not isinstance(arg, str) or '\0' in arg or len(arg) > 32768 for arg in argv):
                raise ControlError('invalid argv')
            if not argv[0] or any(key in request for key in ('server', 'tool', 'arguments')):
                raise ControlError('invalid command request')
        else:
            if request.get('server') not in ('kali', 'hexstrike') or 'argv' in request or 'pty' in request:
                raise ControlError('invalid MCP request')
            if request['kind'] == 'mcp':
                tool = request.get('tool')
                if not isinstance(tool, str) or not 1 <= len(tool) <= 256 or '\0' in tool:
                    raise ControlError('invalid MCP tool')
                if not isinstance(request.get('arguments', {}), dict):
                    raise ControlError('MCP arguments must be an object')
        if 'pty' in request:
            size = request['pty']
            if not isinstance(size, dict) or set(size) != {'rows', 'cols'}:
                raise ControlError('invalid terminal size')
            integer(size['rows'], 1, 1000)
            integer(size['cols'], 1, 1000)
        if len(encode(request)) > MAX_FRAME - 4096:
            raise ControlError('run request too large')
        return request

    async def start(self, request: dict, request_id: str | None = None) -> dict:
        async with self.mutation_lock:
            return await self._start(request, request_id)

    async def _start(self, request: dict, request_id: str | None) -> dict:
        if self.closed:
            raise ControlError('supervisor is stopping')
        request = self.validate_request(request)
        run_id = identifier(request_id) if request_id is not None else str(uuid.uuid4())
        digest = hashlib.sha256(encode(request)).hexdigest()
        if run_id in self.runs:
            run = self.runs[run_id]
            self.current(run, active=False)
            if run.record['requestSha256'] != digest:
                raise ControlError('start request UUID reused with different arguments')
            return copy.deepcopy(run.snapshot)
        if len(self.runs) >= MAX_RUNS:
            raise ControlError('run store capacity reached')
        if sum(run.task is not None and not run.task.done() for run in self.runs.values()) >= MAX_ACTIVE:
            raise ControlError('active run capacity reached')
        directory = self.store / run_id
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            raise ControlError('interrupted run allocation; execution will not be replayed') from None
        fsync_dir(self.store)
        snapshot = dict(id=run_id, project=self.config['project'], generation=self.config['generation'],
                        actor=request['actor'], kind=request['kind'], state='running', exitCode=None,
                        signal=None, cancelRequested=False, captureComplete=False, outputBytes=0,
                        ownerEpoch=0, startedAt=now(), endedAt=None)
        run = Run(directory, dict(schema=1, snapshot=snapshot, request=request,
                                  requestSha256=digest, events=[]))
        self.runs[run_id] = run
        gate_read = gate_write = slave = input_read = None
        launch_error = None
        launch_cancelled = False
        try:
            run.output_fd = os.open(directory / 'output.bin', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.fsync(run.output_fd)
            run.save()
            run.boundary = self.boundaries.create(run_id)
            gate_read, gate_write = os.pipe()
            atomic_json(directory / 'exec.json', request)
            argv = [sys.executable, '-I', str(Path(__file__).resolve()), '--exec', str(directory / 'exec.json'),
                    '--gate-fd', str(gate_read)]
            env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'HOME': str(self.work), 'LANG': 'C.UTF-8', 'TERM': 'xterm-256color',
                   'PYTHONUNBUFFERED': '1'}
            if 'pty' in request:
                master, slave = os.openpty()
                run.pty_fd = run.input_fd = master
                self.set_size(master, request['pty']['rows'], request['pty']['cols'])
                os.set_blocking(master, False)
                run.process = await asyncio.create_subprocess_exec(
                    *argv, stdin=slave, stdout=slave, stderr=slave, env=env,
                    cwd=request['cwd'], start_new_session=True, pass_fds=(gate_read,))
                os.close(slave)
                slave = None
                run.readers.append(asyncio.create_task(self.drain_pty(run)))
            else:
                input_read, run.input_fd = os.pipe()
                os.set_blocking(run.input_fd, False)
                run.process = await asyncio.create_subprocess_exec(
                    *argv, stdin=input_read, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT, env=env, cwd=request['cwd'],
                    start_new_session=True, pass_fds=(gate_read,))
                os.close(input_read)
                input_read = None
                run.readers.append(asyncio.create_task(self.drain_pipe(run)))
            run.boundary.attach(run.process.pid)
            run.record['pid'] = run.process.pid
            run.save()
            os.write(gate_write, b'G')
            run.task = asyncio.create_task(self.watch(run))
        except (Exception, asyncio.CancelledError) as error:
            launch_error = type(error).__name__
            launch_cancelled = isinstance(error, asyncio.CancelledError)
            run.record['failure'] = 'launch failed: ' + type(error).__name__
            run.reason = 'unknown'
            if run.process is not None:
                # The gate is still closed on attachment failure. Killing the
                # launcher cannot miss an executed child in that case.
                if run.process.returncode is None:
                    run.process.kill()
                run.task = asyncio.create_task(self.watch(run))
            else:
                if run.boundary is not None:
                    run.boundary.kill()
                    if run.boundary.empty():
                        run.boundary.remove()
                snapshot.update(state='unknown', endedAt=now(), captureComplete=False)
                run.save()
                if run.output_fd is not None:
                    os.close(run.output_fd)
                    run.output_fd = None
                if run.input_fd is not None:
                    os.close(run.input_fd)
                    run.input_fd = run.pty_fd = None
        finally:
            for fd in (gate_read, gate_write, slave, input_read):
                if fd is not None:
                    os.close(fd)
        if launch_cancelled:
            raise asyncio.CancelledError()
        if launch_error is not None:
            raise ControlError(f'run {run_id} launch failed ({launch_error}); status remains queryable')
        return copy.deepcopy(snapshot)

    async def drain_pipe(self, run: Run) -> None:
        assert run.process is not None and run.process.stdout is not None
        try:
            while data := await run.process.stdout.read(MAX_CHUNK):
                run.append(data)
        except Exception:
            run.capture_failed = True
            run.reason = 'unknown'
            raise

    async def drain_pty(self, run: Run) -> None:
        assert run.pty_fd is not None
        try:
            while True:
                try:
                    data = os.read(run.pty_fd, MAX_CHUNK)
                except BlockingIOError:
                    await fd_ready(run.pty_fd)
                    continue
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                run.append(data)
        except Exception:
            run.capture_failed = True
            run.reason = 'unknown'
            raise

    async def watch(self, run: Run) -> None:
        assert run.process is not None
        deadline = time.monotonic() + run.record['request']['timeoutMs'] / 1000
        stopped = drained = False
        try:
            while run.process.returncode is None:
                if run.reason is not None:
                    break
                if time.monotonic() >= deadline:
                    run.reason = 'timed_out'
                    run.record['terminationReason'] = 'deadline'
                    run.save()
                    break
                await asyncio.sleep(0.01)
            # Includes detached descendants even after the original leader has
            # exited. No successful native exit implies descendant completion.
            if run.boundary is not None:
                run.boundary.kill()
                stop_deadline = time.monotonic() + 5
                while not run.boundary.empty():
                    if time.monotonic() >= stop_deadline:
                        raise ControlError('descendant termination not observed')
                    await asyncio.sleep(0.01)
                stopped = True
            else:
                stopped = run.process.returncode is not None
            await asyncio.wait_for(run.process.wait(), 5)
            await asyncio.wait_for(asyncio.gather(*run.readers), 5)
            drained = True
        except Exception as error:
            run.record['failure'] = 'supervision incomplete: ' + type(error).__name__
            run.reason = 'unknown'
            # Best effort again, but never promote unobserved cleanup to success.
            if run.boundary is not None:
                try:
                    run.boundary.kill()
                except OSError:
                    pass
        finally:
            for task in run.readers:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*run.readers, return_exceptions=True)
            async with run.io_lock:
                if run.input_fd is not None:
                    os.close(run.input_fd)
                    run.pty_fd = run.input_fd = None
            if run.output_fd is not None:
                os.fsync(run.output_fd)
                os.close(run.output_fd)
                run.output_fd = None
            rc = run.process.returncode
            run.snapshot['exitCode'] = rc if rc is not None and rc >= 0 else None
            run.snapshot['signal'] = -rc if rc is not None and rc < 0 else None
            run.snapshot['captureComplete'] = stopped and drained and not run.capture_failed
            run.snapshot['state'] = run.reason or ('exited' if rc is not None else 'unknown')
            if not run.snapshot['captureComplete']:
                run.snapshot['state'] = 'unknown'
            self.collect_mcp_result(run)
            run.snapshot['endedAt'] = now()
            run.save()
            if stopped and run.boundary is not None:
                try:
                    run.boundary.remove()
                except OSError:
                    # An empty group left on disk is safe and recovered later.
                    pass

    def collect_mcp_result(self, run: Run) -> None:
        if run.snapshot['kind'] == 'command':
            return
        try:
            result = read_json(run.directory / 'mcp-result.json', MAX_MCP_RESULT)
            serialized = encode(result)
            if not isinstance(result, dict):
                raise ValueError()
            if len(serialized) <= MAX_SNAPSHOT_RESULT:
                run.snapshot['mcpResult'] = result
            else:
                # Runner also writes the exact envelope into combined output;
                # read(offset) is the bounded transport for large MCP results.
                reference = {
                    'artifact': 'mcp-result.json', 'sha256': hashlib.sha256(serialized).hexdigest(),
                    'bytes': len(serialized), 'inCombinedOutput': True,
                    'outcome': result.get('outcome'), 'inline': False,
                }
                # Large source inventories need not hide a small actual tool
                # result from status consumers. The full envelope stays in the
                # original output in every case.
                for key in ('result', 'error', 'observedFacts', 'cacheProvenance'):
                    if key in result:
                        candidate = {**reference, key: result[key]}
                        if len(encode(candidate)) <= MAX_SNAPSHOT_RESULT:
                            reference = candidate
                run.snapshot['mcpResult'] = reference
            if result.get('outcome') == 'timed_out' and run.snapshot['state'] == 'exited':
                run.snapshot['state'] = 'timed_out'
        except FileNotFoundError:
            run.snapshot['mcpResult'] = {'outcome': 'unknown', 'error': 'runner result was not committed'}
            if run.snapshot['state'] == 'exited' and run.snapshot['exitCode'] == 0:
                run.snapshot['state'] = 'unknown'
        except (ValueError, OSError, ControlError):
            run.snapshot['mcpResult'] = {'outcome': 'unknown', 'error': 'runner result could not be read'}
            run.snapshot['state'] = 'unknown'

    async def input(self, run_id: str, data: str, epoch: int) -> dict:
        run = self.get(run_id)
        integer(epoch, 0, 2**53 - 1)
        if not isinstance(data, str) or len(data) > 4 * ((MAX_CHUNK + 2) // 3):
            raise ControlError('invalid input chunk')
        try:
            raw = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error):
            raise ControlError('invalid base64 input') from None
        if len(raw) > MAX_CHUNK:
            raise ControlError('input chunk too large')
        async with run.io_lock:
            self.current(run)
            if epoch != run.snapshot['ownerEpoch']:
                raise ControlError('stale ownership epoch')
            try:
                if run.input_fd is not None:
                    # Direct nonblocking writes never leave an unbounded
                    # asyncio transport buffer after a delivery timeout.
                    await asyncio.wait_for(write_fd(run.input_fd, raw), 1)
                else:
                    raise ControlError('stdin is closed')
            except (OSError, asyncio.TimeoutError):
                raise ControlError('stdin delivery incomplete; do not blindly replay input') from None
        return copy.deepcopy(run.snapshot)

    @staticmethod
    def set_size(fd: int, rows: int, cols: int) -> None:
        integer(rows, 1, 1000)
        integer(cols, 1, 1000)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

    async def resize(self, run_id: str, rows: int, cols: int, epoch: int) -> dict:
        run = self.get(run_id)
        async with run.io_lock:
            self.current(run)
            integer(epoch, 0, 2**53 - 1)
            if epoch != run.snapshot['ownerEpoch']:
                raise ControlError('stale ownership epoch')
            if run.pty_fd is None:
                raise ControlError('run has no PTY')
            self.set_size(run.pty_fd, rows, cols)
        return copy.deepcopy(run.snapshot)

    async def takeover(self, run_id: str) -> dict:
        run = self.get(run_id)
        async with run.io_lock:
            self.current(run)
            run.snapshot['ownerEpoch'] += 1
            run.save()
        return copy.deepcopy(run.snapshot)

    async def cancel(self, run_id: str) -> dict:
        run = self.get(run_id)
        self.current(run, active=False)
        run.snapshot['cancelRequested'] = True
        if run.snapshot['state'] == 'running' and run.process is not None and run.process.returncode is None:
            run.reason = run.reason or 'cancelled'
            run.record['terminationReason'] = 'cancel requested'
        run.save()
        return copy.deepcopy(run.snapshot)

    def read(self, run_id: str, offset: int, limit: int = MAX_CHUNK) -> dict:
        run = self.get(run_id)
        integer(offset, 0, run.snapshot['outputBytes'])
        integer(limit, 1, MAX_CHUNK)
        with (run.directory / 'output.bin').open('rb') as output:
            output.seek(offset)
            data = output.read(min(limit, run.snapshot['outputBytes'] - offset))
        return dict(run=copy.deepcopy(run.snapshot), offset=offset,
                    nextOffset=offset + len(data), data=base64.b64encode(data).decode('ascii'))

    async def disconnected(self) -> None:
        # Channel loss is not cancellation. Deadlines and capture continue. This
        # durable fact is separate from the observed native process outcome.
        for run in self.runs.values():
            if run.snapshot['state'] == 'running':
                run.record['disconnectCount'] = run.record.get('disconnectCount', 0) + 1
                run.record['lastDisconnectAt'] = now()
                run.save()

    async def handle(self, request: object) -> dict:
        if not isinstance(request, dict):
            raise ControlError('invalid request envelope')
        request_id = identifier(request.get('id'))
        response = dict(v=1, id=request_id, project=self.config['project'], generation=self.config['generation'])
        try:
            # Check all credentials on every operation, including reads/ping.
            token = request.get('token')
            authenticated = isinstance(token, str) and token.isascii() and hmac.compare_digest(token, self.config['token'])
            project_ok = request.get('project') == self.config['project']
            generation_ok = request.get('generation') == self.config['generation']
            if not (authenticated and project_ok and generation_ok):
                raise ControlError('authentication or generation rejected')
            if type(request.get('v')) is not int or request['v'] != 1:
                raise ControlError('unsupported protocol version')
            args = request.get('args')
            if not isinstance(args, dict):
                raise ControlError('args must be an object')
            op = request.get('op')
            if op == 'ping':
                result = {'ready': not self.closed}
            elif op == 'poweroff':
                if args:
                    raise ControlError('poweroff accepts no arguments')
                async with self.mutation_lock:
                    self.closed = True
                # Acceptance is not VM exit. The transport sends this receipt
                # before asking systemd to stop the supervisor and the guest.
                result = {'requested': True}
            elif op == 'start':
                result = await self.start(args, request_id)
            elif op == 'status':
                result = copy.deepcopy(self.get(args.get('id')).snapshot)
            elif op == 'read':
                result = self.read(args.get('id'), args.get('offset'), args.get('limit', MAX_CHUNK))
            elif op == 'list':
                result = [copy.deepcopy(run.snapshot) for run in self.runs.values()]
                # List remains bounded even when many runs have inline results.
                if len(encode(result)) > MAX_FRAME - 1024:
                    for item in result:
                        if 'mcpResult' in item:
                            item['mcpResult'] = {'inline': False, 'availableVia': 'status'}
            elif op == 'input':
                result = await self.input(args.get('id'), args.get('data'), args.get('ownerEpoch'))
            elif op == 'resize':
                result = await self.resize(args.get('id'), args.get('rows'), args.get('cols'), args.get('ownerEpoch'))
            elif op == 'takeover':
                result = await self.takeover(args.get('id'))
            elif op == 'cancel':
                result = await self.cancel(args.get('id'))
            else:
                raise ControlError('unsupported operation')
            response.update(ok=True, result=result)
        except ControlError as error:
            response.update(ok=False, error=str(error))
        except (OSError, ValueError, TypeError, KeyError):
            response.update(ok=False, error='operation failed; consult durable run state')
        if len(encode(response)) > MAX_FRAME:
            response.pop('result', None)
            response.update(ok=False, error='response exceeds frame limit; use bounded read')
        return response

    async def close(self) -> None:
        self.closed = True
        for run in self.runs.values():
            if run.task is not None and not run.task.done():
                run.reason = run.reason or 'unknown'
                run.record['terminationReason'] = 'supervisor shutdown'
                run.save()
        await asyncio.gather(*(run.task for run in self.runs.values() if run.task is not None), return_exceptions=False)
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None


async def poweroff_guest() -> None:
    process = await asyncio.create_subprocess_exec(
        '/usr/bin/systemctl', '--no-block', 'poweroff',
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL)
    try:
        code = await asyncio.wait_for(process.wait(), 5)
        if code != 0:
            raise ControlError(f'guest OS rejected poweroff ({code})')
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def serve_fd(supervisor: Supervisor, fd: int) -> None:
    """One connection; caller owns fd. Also accepts a socketpair fixture fd."""
    os.set_blocking(fd, False)
    frames = Frames()
    try:
        while True:
            try:
                chunk = os.read(fd, MAX_CHUNK)
            except BlockingIOError:
                await fd_ready(fd)
                continue
            if not chunk:
                break
            for frame in frames.feed(chunk):
                if frame is None:
                    # No valid request ID: discard without amplifying or echoing
                    # untrusted data. The next complete frame remains usable.
                    continue
                try:
                    request = decode(frame)
                    reply = await supervisor.handle(request)
                except (ValueError, UnicodeError, RecursionError, ControlError):
                    continue
                await asyncio.wait_for(write_fd(fd, encode(reply) + b'\n'), 5)
                if request.get('op') == 'poweroff' and reply.get('ok'):
                    await poweroff_guest()
    finally:
        await supervisor.disconnected()


def child_exec(request_path: Path, gate_fd: int) -> int:
    # Only the parent can release this inherited FD after durable allocation and
    # successful cgroup attachment. No user command runs before that point.
    try:
        if os.read(gate_fd, 1) != b'G':
            return 125
    finally:
        os.close(gate_fd)
    request = read_json(request_path)
    if 'pty' in request:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    if request['kind'] == 'command':
        argv = request['argv']
    else:
        argv = [sys.executable, '-I', str(Path(__file__).with_name('mcp_runner.py')),
                '--request', str(request_path), '--result', str(request_path.parent / 'mcp-result.json')]
    try:
        os.execvpe(argv[0], argv, os.environ)
    except OSError as error:
        os.write(2, ('exec failed: ' + type(error).__name__ + '\n').encode())
        return 127 if error.errno == errno.ENOENT else 126


async def daemon(config_path: Path, channel: Path) -> None:
    config = validate_config(read_json(config_path, 4096))
    WORK.mkdir(exist_ok=True, mode=0o700)
    supervisor = await Supervisor.open(config, STORE, WORK)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def channels() -> None:
        while not stop.is_set():
            fd = None
            try:
                fd = os.open(channel, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)
                if not stat.S_ISCHR(os.fstat(fd).st_mode):
                    raise ControlError('control channel must be a character device')
                if os.isatty(fd):
                    attrs = termios.tcgetattr(fd)
                    attrs[0] = attrs[1] = attrs[3] = 0
                    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
                    attrs[6][termios.VMIN] = 1
                    attrs[6][termios.VTIME] = 0
                    termios.tcsetattr(fd, termios.TCSANOW, attrs)
                await serve_fd(supervisor, fd)
            except (OSError, asyncio.TimeoutError):
                # A absent/disconnected virtio port cannot authorize any work.
                # Continue supervising existing descendants while reconnecting.
                pass
            finally:
                if fd is not None:
                    os.close(fd)
            await asyncio.sleep(0.25)

    connection = asyncio.create_task(channels())
    stopping = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait((connection, stopping), return_when=asyncio.FIRST_COMPLETED)
        if connection.done():
            connection.result()
    finally:
        connection.cancel()
        stopping.cancel()
        await asyncio.gather(connection, stopping, return_exceptions=True)
        await supervisor.close()


def main() -> int:
    parser = argparse.ArgumentParser(description='Authenticated Agent Smith guest supervisor')
    parser.add_argument('--config', type=Path, default=FW_CONFIG)
    parser.add_argument('--channel', type=Path, default=CHANNEL)
    parser.add_argument('--exec', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--gate-fd', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.exec is not None:
        if args.gate_fd is None:
            return 125
        return child_exec(args.exec, args.gate_fd)
    try:
        asyncio.run(daemon(args.config, args.channel))
    except Exception as error:
        # Never print the configuration, request, token, or exception payload.
        print('agent-smith supervisor failed closed: ' + type(error).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
