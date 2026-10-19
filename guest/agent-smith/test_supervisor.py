"""Owned subprocess fixtures. Never writes host cgroups or uses installed MCPs.

Run after integration: python3 -m unittest discover -s guest/agent-smith -p 'test_*.py'
GroupFactory exercises real pipes/PTY/processes but cannot contain setsid escapes.
Main must separately exercise CgroupV2Factory, detached descendants and installed
MCPs in the actual guest. There is deliberately no fixture boundary CLI option.
"""

import asyncio
import base64
import copy
import json
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import unittest
import uuid

import supervisor


def process_status(pid: int) -> tuple[str, int] | None:
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return fields[0], int(fields[2])
    except (FileNotFoundError, ProcessLookupError):
        return None


class GroupBoundary:
    """Test-owned process groups only; explicitly weaker than production."""

    def __init__(self):
        self.pid = None

    def attach(self, pid: int) -> None:
        if os.getpgid(pid) != pid:
            raise RuntimeError('fixture child did not establish its own process group')
        self.pid = pid

    def kill(self) -> None:
        if self.pid is not None:
            try:
                os.killpg(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def empty(self) -> bool:
        if self.pid is None:
            return True
        for entry in Path('/proc').iterdir():
            if entry.name.isdecimal():
                status = process_status(int(entry.name))
                if status is not None and status[1] == self.pid and status[0] != 'Z':
                    return False
        return True

    def remove(self) -> None:
        if not self.empty():
            raise RuntimeError('fixture still has running descendants')


class GroupFactory:
    def __init__(self):
        self.groups = {}

    def create(self, run_id: str) -> GroupBoundary:
        boundary = GroupBoundary()
        self.groups[run_id] = boundary
        return boundary

    def recover(self, run_id: str) -> GroupBoundary | None:
        return self.groups.get(run_id)


class RefusingBoundary(GroupBoundary):
    def attach(self, pid: int) -> None:
        super().attach(pid)
        raise OSError('fixture cgroup attachment refused')


class RefusingFactory(GroupFactory):
    def create(self, run_id: str) -> RefusingBoundary:
        boundary = RefusingBoundary()
        self.groups[run_id] = boundary
        return boundary


@unittest.skipUnless(sys.platform == 'linux', 'Linux PTY/proc subprocess contract')
class SupervisorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='smith-supervisor-')
        self.root = Path(self.temp.name)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.store = self.root / 'runs'
        self.config = dict(project=str(uuid.uuid4()), generation=str(uuid.uuid4()), token='fixture-token-' + 'x' * 40)
        self.factory = GroupFactory()
        self.supervisor = await supervisor.Supervisor.open(self.config, self.store, self.work, boundaries=self.factory)
        self.sockets = []
        self.connections = []

    async def asyncTearDown(self):
        for sock in self.sockets:
            sock.close()
        for connection in self.connections:
            connection.cancel()
        await asyncio.gather(*self.connections, return_exceptions=True)
        await self.supervisor.close()
        self.temp.cleanup()

    def request(self, code: str, *, timeout: int = 5000, pty: bool = False) -> dict:
        request = dict(actor='human', kind='command', argv=[sys.executable, '-c', code], timeoutMs=timeout)
        if pty:
            request['pty'] = {'rows': 24, 'cols': 80}
        return request

    def envelope(self, op: str, args: dict, **overrides) -> dict:
        value = dict(v=1, id=str(uuid.uuid4()), **self.config, op=op, args=args)
        value.update(overrides)
        return value

    async def finished(self, run_id: str) -> dict:
        run = self.supervisor.get(run_id)
        if run.task is not None:
            await asyncio.wait_for(asyncio.shield(run.task), 10)
        return copy.deepcopy(run.snapshot)

    def output(self, run_id: str) -> bytes:
        output = bytearray()
        offset = 0
        while True:
            result = self.supervisor.read(run_id, offset)
            output.extend(base64.b64decode(result['data']))
            if result['nextOffset'] == offset:
                return bytes(output)
            offset = result['nextOffset']

    async def until_output(self, run_id: str, marker: bytes) -> bytes:
        async with asyncio.timeout(5):
            while True:
                output = self.output(run_id)
                if marker in output:
                    return output
                await asyncio.sleep(0.01)

    def connection(self) -> socket.socket:
        client, server = socket.socketpair()
        client.setblocking(False)
        server.setblocking(False)
        self.sockets.extend((client, server))
        self.connections.append(asyncio.create_task(supervisor.serve_fd(self.supervisor, server.fileno())))
        return client

    async def exchange(self, client: socket.socket, value: dict) -> dict:
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(client, supervisor.encode(value) + b'\n')
        data = bytearray()
        async with asyncio.timeout(5):
            while not data.endswith(b'\n'):
                chunk = await loop.sock_recv(client, supervisor.MAX_CHUNK)
                if not chunk:
                    self.fail('control connection closed before reply')
                data.extend(chunk)
        self.assertLessEqual(len(data), supervisor.MAX_FRAME + 1)
        return json.loads(data)

    async def test_native_nonzero_exit_and_binary_bytes_survive_restart(self):
        """Consumers see native exit 23 and byte-exact merged output after reopen."""
        run = await self.supervisor.start(self.request("import os; os.write(1,b'out\\x00\\xff'); os.write(2,b'err'); raise SystemExit(23)"))
        ended = await self.finished(run['id'])
        self.assertEqual((ended['state'], ended['exitCode'], ended['signal']), ('exited', 23, None))
        self.assertTrue(ended['captureComplete'])
        expected = b'out\x00\xfferr'
        self.assertEqual(self.output(run['id']), expected)
        await self.supervisor.close()
        self.supervisor = await supervisor.Supervisor.open(self.config, self.store, self.work, boundaries=self.factory)
        self.assertEqual(self.supervisor.get(run['id']).snapshot, ended)
        self.assertEqual(self.output(run['id']), expected)

    async def test_signal_outcome_is_not_an_invented_exit_code(self):
        run = await self.supervisor.start(self.request('import os,signal; os.kill(os.getpid(),signal.SIGTERM)'))
        ended = await self.finished(run['id'])
        self.assertEqual((ended['exitCode'], ended['signal']), (None, signal.SIGTERM))
        self.assertTrue(ended['captureComplete'])

    async def test_timeout_retains_partial_bytes_and_stops_descendant(self):
        code = (
            "import subprocess,sys,time,os; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "os.write(1,('child='+str(p.pid)+'\\npartial\\n').encode()); time.sleep(60)"
        )
        run = await self.supervisor.start(self.request(code, timeout=750))
        ended = await self.finished(run['id'])
        output = self.output(run['id'])
        self.assertIn(b'partial\n', output)
        child = int(output.split(b'child=')[1].split(b'\n')[0])
        status = process_status(child)
        self.assertTrue(status is None or status[0] == 'Z')
        self.assertEqual((ended['state'], ended['exitCode'], ended['signal']), ('timed_out', None, signal.SIGKILL))
        self.assertFalse(ended['cancelRequested'])
        self.assertTrue(ended['captureComplete'])

    async def test_leader_exit_does_not_leave_output_holding_descendant(self):
        code = (
            "import subprocess,sys,os; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "os.write(1,('child='+str(p.pid)+'\\n').encode()); raise SystemExit(7)"
        )
        run = await self.supervisor.start(self.request(code))
        ended = await self.finished(run['id'])
        child = int(self.output(run['id']).split(b'child=')[1].split(b'\n')[0])
        status = process_status(child)
        self.assertTrue(status is None or status[0] == 'Z')
        self.assertEqual(ended['exitCode'], 7)
        self.assertTrue(ended['captureComplete'])

    async def test_cancel_request_is_distinct_from_observed_outcome(self):
        run = await self.supervisor.start(self.request("import os,time; os.write(1,b'ready'); time.sleep(60)"))
        await self.until_output(run['id'], b'ready')
        requested = await self.supervisor.cancel(run['id'])
        self.assertTrue(requested['cancelRequested'])
        self.assertEqual(requested['state'], 'running')
        self.assertFalse(requested['captureComplete'])
        ended = await self.finished(run['id'])
        self.assertEqual((ended['state'], ended['signal']), ('cancelled', signal.SIGKILL))
        self.assertTrue(ended['captureComplete'])
        natural = await self.supervisor.start(self.request('raise SystemExit(4)'))
        await self.finished(natural['id'])
        late = await self.supervisor.cancel(natural['id'])
        self.assertEqual((late['state'], late['exitCode']), ('exited', 4))
        self.assertTrue(late['cancelRequested'])

    async def test_pty_takeover_blocks_old_input_and_resize_and_delivers_size(self):
        code = (
            "import os,sys; print('ready',flush=True); "
            "line=sys.stdin.readline(); size=os.get_terminal_size(); "
            "print('received='+line.strip()+';size='+str(size.lines)+'x'+str(size.columns),flush=True)"
        )
        run = await self.supervisor.start(self.request(code, pty=True))
        await self.until_output(run['id'], b'ready')
        owner = await self.supervisor.takeover(run['id'])
        with self.assertRaisesRegex(supervisor.ControlError, 'epoch'):
            await self.supervisor.input(run['id'], base64.b64encode(b'OLD\n').decode(), 0)
        with self.assertRaisesRegex(supervisor.ControlError, 'epoch'):
            await self.supervisor.resize(run['id'], 2, 3, 0)
        await self.supervisor.resize(run['id'], 41, 101, owner['ownerEpoch'])
        await self.supervisor.input(run['id'], base64.b64encode(b'NEW\n').decode(), owner['ownerEpoch'])
        ended = await self.finished(run['id'])
        self.assertIn(b'received=NEW;size=41x101', self.output(run['id']))
        self.assertNotIn(b'OLD', self.output(run['id']))
        self.assertEqual(ended['exitCode'], 0)
        self.assertTrue(ended['captureComplete'])

    async def test_pty_control_c_reports_native_signal(self):
        code = "import signal,time; signal.signal(signal.SIGINT,signal.SIG_DFL); print('ready',flush=True); time.sleep(60)"
        run = await self.supervisor.start(self.request(code, pty=True))
        await self.until_output(run['id'], b'ready')
        await self.supervisor.input(run['id'], base64.b64encode(b'\x03').decode(), 0)
        ended = await self.finished(run['id'])
        self.assertEqual((ended['exitCode'], ended['signal']), (None, signal.SIGINT))
        self.assertFalse(ended['cancelRequested'])

    async def test_pipe_input_is_delivered_without_a_terminal(self):
        code = "import os; os.write(1,b'ready'); data=os.read(0,4); os.write(1,b'got:'+data)"
        run = await self.supervisor.start(self.request(code))
        await self.until_output(run['id'], b'ready')
        await self.supervisor.input(run['id'], base64.b64encode(b'\x00\xffab').decode(), 0)
        ended = await self.finished(run['id'])
        self.assertEqual(self.output(run['id']), b'readygot:\x00\xffab')
        self.assertEqual(ended['exitCode'], 0)

    async def test_attachment_failure_cannot_execute_requested_command(self):
        await self.supervisor.close()
        self.supervisor = await supervisor.Supervisor.open(self.config, self.store, self.work, boundaries=RefusingFactory())
        run_id = str(uuid.uuid4())
        with self.assertRaisesRegex(supervisor.ControlError, 'launch failed'):
            await self.supervisor.start(self.request("from pathlib import Path; Path('forbidden').write_text('executed')"), run_id)
        ended = await self.finished(run_id)
        self.assertFalse((self.work / 'forbidden').exists())
        self.assertEqual(ended['state'], 'unknown')

    async def test_reconnect_reads_original_offsets_without_stopping_run(self):
        client = self.connection()
        request = self.envelope('start', self.request("import os,time; os.write(1,b'first'); time.sleep(.4); os.write(1,b'second')"))
        reply = await self.exchange(client, request)
        run_id = reply['result']['id']
        await self.until_output(run_id, b'first')
        first = await self.exchange(client, self.envelope('read', {'id': run_id, 'offset': 0, 'limit': 5}))
        self.assertEqual(base64.b64decode(first['result']['data']), b'first')
        client.shutdown(socket.SHUT_RDWR)
        await asyncio.wait_for(self.connections[-1], 3)
        self.assertFalse(self.supervisor.get(run_id).snapshot['cancelRequested'])
        fresh = self.connection()
        replay = await self.exchange(fresh, request)
        self.assertEqual(replay['result']['id'], run_id)
        ended = await self.finished(run_id)
        second = await self.exchange(fresh, self.envelope('read', {'id': run_id, 'offset': 5}))
        self.assertEqual(base64.b64decode(second['result']['data']), b'second')
        self.assertEqual(ended['exitCode'], 0)
        self.assertEqual(self.supervisor.get(run_id).record['disconnectCount'], 1)

    async def test_authentication_applies_to_reads_and_stale_generation_mutations(self):
        run = await self.supervisor.start(self.request("print('historical')"))
        await self.finished(run['id'])
        original_generation = self.config['generation']
        await self.supervisor.close()
        self.config['generation'] = str(uuid.uuid4())
        self.supervisor = await supervisor.Supervisor.open(self.config, self.store, self.work, boundaries=self.factory)
        for op, args, change in (
            ('read', {'id': run['id'], 'offset': 0}, {'token': 'wrong'}),
            ('ping', {}, {'generation': original_generation}),
            ('list', {}, {'project': str(uuid.uuid4())}),
        ):
            response = await self.supervisor.handle(self.envelope(op, args, **change))
            self.assertFalse(response['ok'])
            self.assertNotIn(self.config['token'], json.dumps(response))
        for op, args in (
            ('input', {'id': run['id'], 'data': 'Cg==', 'ownerEpoch': 0}),
            ('takeover', {'id': run['id']}),
            ('cancel', {'id': run['id']}),
        ):
            response = await self.supervisor.handle(self.envelope(op, args))
            self.assertFalse(response['ok'])
            self.assertIn('stale run generation', response['error'])
        response = await self.supervisor.handle(self.envelope('read', {'id': run['id'], 'offset': 0}))
        self.assertTrue(response['ok'])
        self.assertEqual(base64.b64decode(response['result']['data']), b'historical\n')

    async def test_poweroff_authentication_and_closed_execution_boundary(self):
        for change in ({'token': 'wrong'}, {'project': str(uuid.uuid4())},
                       {'generation': str(uuid.uuid4())}):
            response = await self.supervisor.handle(self.envelope('poweroff', {}, **change))
            self.assertFalse(response['ok'])
        refused = await self.supervisor.handle(self.envelope('poweroff', {'command': 'unsupported'}))
        self.assertFalse(refused['ok'])
        # Refused shutdown requests must leave legitimate work usable.
        run = await self.supervisor.start(self.request("print('retained-before-poweroff')"))
        await self.finished(run['id'])
        accepted = await self.supervisor.handle(self.envelope('poweroff', {}))
        self.assertTrue(accepted['ok'])
        blocked = await self.supervisor.handle(self.envelope('start', self.request(
            "from pathlib import Path; Path('after-poweroff').write_text('must not execute')")))
        self.assertFalse(blocked['ok'])
        self.assertFalse((self.work / 'after-poweroff').exists())
        historical = await self.supervisor.handle(self.envelope('read', {'id': run['id'], 'offset': 0}))
        self.assertTrue(historical['ok'])
        self.assertEqual(base64.b64decode(historical['result']['data']), b'retained-before-poweroff\n')

    async def test_start_replay_is_durable_and_argument_reuse_is_rejected(self):
        request_id = str(uuid.uuid4())
        request = self.request("from pathlib import Path; p=Path('counter'); p.write_text(p.read_text()+'x' if p.exists() else 'x')")
        await self.supervisor.start(request, request_id)
        await self.finished(request_id)
        await self.supervisor.close()
        self.supervisor = await supervisor.Supervisor.open(self.config, self.store, self.work, boundaries=self.factory)
        await self.supervisor.start(request, request_id)
        self.assertEqual((self.work / 'counter').read_text(), 'x')
        with self.assertRaisesRegex(supervisor.ControlError, 'reused'):
            await self.supervisor.start(self.request("print('different')"), request_id)

    async def test_unobserved_restart_state_is_unknown_and_never_reexecuted(self):
        request = self.request("from pathlib import Path; Path('once').write_text('once')")
        run = await self.supervisor.start(request)
        await self.finished(run['id'])
        await self.supervisor.close()
        path = self.store / run['id'] / 'state.json'
        record = json.loads(path.read_bytes())
        record['snapshot'].update(state='running', exitCode=None, signal=None, captureComplete=False, endedAt=None)
        supervisor.atomic_json(path, record)
        (self.work / 'once').unlink()
        self.supervisor = await supervisor.Supervisor.open(self.config, self.store, self.work, boundaries=self.factory)
        recovered = await self.supervisor.start(request, run['id'])
        self.assertEqual(recovered['state'], 'unknown')
        self.assertFalse(recovered['captureComplete'])
        self.assertIsNone(recovered['exitCode'])
        self.assertFalse((self.work / 'once').exists())

    async def test_oversized_frame_and_bad_json_do_not_desynchronize_channel(self):
        client = self.connection()
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(client, b'x' * (supervisor.MAX_FRAME + 1) + b'\n')
        await loop.sock_sendall(client, b'{"id":NaN}\n{"id":1,"id":2}\n')
        reply = await self.exchange(client, self.envelope('ping', {}))
        self.assertTrue(reply['ok'])
        run = await self.supervisor.start(self.request("import os; os.write(1,b'a'*140000)"))
        await self.finished(run['id'])
        chunk = await self.exchange(client, self.envelope('read', {'id': run['id'], 'offset': 0}))
        self.assertEqual(len(base64.b64decode(chunk['result']['data'])), supervisor.MAX_CHUNK)
        rejected = await self.exchange(client, self.envelope('read', {'id': run['id'], 'offset': 0, 'limit': supervisor.MAX_CHUNK + 1}))
        self.assertFalse(rejected['ok'])

    async def test_disconnect_drops_partial_execution_frame(self):
        client = self.connection()
        request = self.envelope('start', self.request("from pathlib import Path; Path('unexpected').touch()"))
        wire = supervisor.encode(request)
        split = len(wire) // 2
        await asyncio.get_running_loop().sock_sendall(client, wire[:split])
        client.shutdown(socket.SHUT_WR)
        await asyncio.wait_for(self.connections[-1], 3)
        fresh = self.connection()
        await asyncio.get_running_loop().sock_sendall(fresh, wire[split:] + b'\n')
        response = await self.exchange(fresh, self.envelope('list', {}))
        self.assertEqual(response['result'], [])
        self.assertFalse((self.work / 'unexpected').exists())


if __name__ == '__main__':
    unittest.main()
