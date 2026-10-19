"""Metadata contracts; installed MCP execution remains a guest acceptance test."""

import asyncio
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error

import mcp_runner


class McpReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.loop = asyncio.get_running_loop()
        self.requested = asyncio.Event()
        self.release = threading.Event()
        self.release.set()
        self.requests = []
        self.status = 200
        self.body = b'{"status":"healthy"}'
        case = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                case.requests.append(self.path)
                case.loop.call_soon_threadsafe(case.requested.set)
                if not case.release.wait(5):
                    return
                try:
                    self.send_response(case.status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(case.body)))
                    self.end_headers()
                    self.wfile.write(case.body)
                except (BrokenPipeError, ConnectionResetError):
                    # Expected when testing the caller's readiness deadline.
                    pass

            def log_message(self, format, *args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.api = SimpleNamespace(pid=1, returncode=None)
        listener = patch.object(mcp_runner, 'check_listener', return_value=True)
        listener.start()
        self.addCleanup(listener.stop)

    async def asyncTearDown(self):
        self.release.set()
        await asyncio.to_thread(self.server.shutdown)
        self.server.server_close()
        self.thread.join()

    async def test_health_initialization_completes_without_abandoned_requests(self):
        self.release.clear()
        readiness = asyncio.create_task(mcp_runner.wait_api(self.api, self.port, time.monotonic() + 3))
        try:
            await asyncio.wait_for(self.requested.wait(), 2)
            # The response depends on another coroutine: a blocking 250 ms
            # probe must abandon its first request before this can release it.
            self.assertFalse(readiness.done())
            self.release.set()
            await asyncio.wait_for(readiness, 2)
            self.assertEqual(self.requests, ['/health'])
        finally:
            self.release.set()
            if not readiness.done():
                readiness.cancel()
            await asyncio.gather(readiness, return_exceptions=True)

    async def test_health_http_failure_surfaces_instead_of_retry_timeout(self):
        self.status = 503
        with self.assertRaises(urllib.error.HTTPError) as caught:
            await mcp_runner.wait_api(self.api, self.port, time.monotonic() + 3)
        self.assertEqual(caught.exception.code, 503)
        self.assertEqual(self.requests, ['/health'])

    async def test_health_request_cannot_extend_readiness_deadline(self):
        self.release.clear()
        with self.assertRaisesRegex(TimeoutError, 'readiness timed out'):
            await mcp_runner.wait_api(self.api, self.port, time.monotonic() + 1)
        self.assertEqual(self.requests, ['/health'])


class McpResultTests(unittest.TestCase):
    def test_timeout_with_output_cannot_be_promoted_by_upstream_success(self):
        upstream = {'stdout': 'partial scan', 'stderr': '', 'return_code': -1,
                    'success': True, 'timed_out': True, 'partial_results': 'partial scan',
                    'cached': False, 'vendor_extension': {'receipt': 7}}
        raw = {'content': [{'type': 'text', 'text': json.dumps(upstream)}],
               'isError': False, '_meta': {'cache_hit': True, 'vendor': {'trace': 'fixture'}}}
        before = copy.deepcopy(raw)
        outcome, code, facts = mcp_runner.result_outcome(raw)
        self.assertEqual((outcome, code), ('timed_out', 124))
        self.assertTrue(facts['timedOut'])
        self.assertIn({'path': '$._meta.cache_hit', 'value': True}, facts['cache'])
        with tempfile.TemporaryDirectory(prefix='smith-mcp-metadata-') as directory:
            path = Path(directory) / 'result.json'
            mcp_runner.commit_result(path, {'result': raw, 'outcome': outcome, 'observedFacts': facts})
            committed = json.loads(path.read_bytes())
            self.assertEqual(committed['result'], before)
            self.assertEqual(json.loads(committed['result']['content'][0]['text']), upstream)

    def test_nested_structured_timeout_wins_and_stdout_text_is_not_status(self):
        raw = {'structuredContent': {'result': {'success': True, 'timed_out': True}}, 'isError': False}
        self.assertEqual(mcp_runner.result_outcome(raw)[:2], ('timed_out', 124))
        ordinary = {'structuredContent': {'success': True, 'stdout': '{"timed_out":true}'}, 'isError': False}
        self.assertEqual(mcp_runner.result_outcome(ordinary)[:2], ('completed', 0))

    def test_native_failure_and_protocol_tool_error_are_not_success(self):
        native = {'content': [{'type': 'text', 'text': json.dumps({'return_code': 2, 'stdout': 'partial'})}], 'isError': False}
        tool_error = {'content': [{'type': 'text', 'text': 'tool rejected input'}], 'isError': True}
        timeout_error = {'structuredContent': {'error': 'HTTP request timed out'}, 'isError': True}
        self.assertEqual(mcp_runner.result_outcome(native)[:2], ('error', 1))
        self.assertEqual(mcp_runner.result_outcome(tool_error)[:2], ('error', 1))
        self.assertEqual(mcp_runner.result_outcome(timeout_error)[:2], ('timed_out', 124))

    def test_cache_disable_uses_advertised_schema_and_does_not_invent_support(self):
        request = {'server': 'hexstrike', 'tool': 'nmap_scan', 'arguments': {'target': '127.0.0.1', 'use_cache': True}}
        tools = [{'name': 'nmap_scan', 'inputSchema': {'properties': {'use_cache': {'type': 'boolean'}}}}]
        arguments, policy = mcp_runner.prepare_call(request, tools)
        self.assertFalse(arguments['use_cache'])
        self.assertEqual(policy['policy'], 'disabled-by-tool-argument')
        arguments, policy = mcp_runner.prepare_call({'server': 'hexstrike', 'tool': 'nmap_scan'}, [{'name': 'nmap_scan'}])
        self.assertNotIn('use_cache', arguments)
        self.assertEqual(policy['policy'], 'upstream-default-unverified')
        with self.assertRaisesRegex(ValueError, 'no second agent loop'):
            mcp_runner.prepare_call({'server': 'hexstrike', 'tool': 'intelligent_scan'}, [{'name': 'intelligent_scan'}])


if __name__ == '__main__':
    unittest.main()
