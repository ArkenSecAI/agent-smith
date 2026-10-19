"""Exercise installed upstream executors with real children, without starting APIs.

AST selection avoids importing unrelated Flask/AI services. Executor, process
registry and telemetry code come from the installed package, not test copies.
The full guest API/MCP route is a separate runtime qualification.
"""
import ast
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time
import traceback
import typing
import unittest


ROOT = Path(os.environ.get('AGENT_SMITH_MCP_TEST_ROOT', '/'))
SOURCES = {
    'kali': ('usr/share/mcp-kali-server/server.py', 'CommandExecutor'),
    'hexstrike': ('usr/share/hexstrike-ai/hexstrike_server.py', 'EnhancedCommandExecutor'),
}


def load_executor(source, name):
    tree = ast.parse(source.read_bytes(), filename=str(source))
    classes = {name, 'ModernVisualEngine', 'ProcessManager', 'TelemetryCollector'}
    assignments = {'active_processes', 'process_lock', 'telemetry', 'COMMAND_TIMEOUT'}
    nodes: list[ast.stmt] = [node for node in tree.body
                            if (isinstance(node, ast.ClassDef) and node.name in classes)
                            or (isinstance(node, ast.Assign) and any(
                                isinstance(target, ast.Name) and target.id in assignments for target in node.targets))]
    namespace = {**vars(typing), 'subprocess': subprocess, 'threading': threading,
                 'time': time, 'traceback': traceback, 'datetime': datetime, 'shlex': shlex,
                 'logger': logging.getLogger('installed-mcp-regression')}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), namespace)
    return namespace[name]


@unittest.skipUnless(all((ROOT / relative).is_file() for relative, _ in SOURCES.values()),
                     'requires both installed MCP package sources')
class InstalledExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executors = {label: load_executor(ROOT / relative, name)
                         for label, (relative, name) in SOURCES.items()}

    def test_timeout_retains_output_without_claiming_success(self):
        for label, executor in self.executors.items():
            with self.subTest(server=label):
                result = executor("printf 'partial-evidence\\n'; exec /bin/sleep 30", timeout=0.3).execute()
                self.assertIs(result['timed_out'], True)
                self.assertIs(result['success'], False)
                self.assertIs(result['partial_results'], True)
                self.assertEqual(result['stdout'], 'partial-evidence\n')

    def test_nonzero_exit_is_not_success_even_with_output(self):
        for label, executor in self.executors.items():
            with self.subTest(server=label):
                result = executor("printf 'failure-evidence\\n'; exit 7", timeout=5).execute()
                self.assertIs(result['timed_out'], False)
                self.assertIs(result['success'], False)
                self.assertEqual(result['return_code'], 7)
                self.assertEqual(result['stdout'], 'failure-evidence\n')

    def test_completed_command_remains_successful(self):
        for label, executor in self.executors.items():
            with self.subTest(server=label):
                result = executor("printf 'complete-evidence\\n'", timeout=5).execute()
                self.assertIs(result['timed_out'], False)
                self.assertIs(result['success'], True)
                self.assertEqual(result['return_code'], 0)
                self.assertEqual(result['stdout'], 'complete-evidence\n')

    def test_kali_tool_argv_preserves_literal_arguments_and_native_failure(self):
        # Kali's /api/tools/nmap passes a list, unlike /api/command. Exercise
        # that real executor path without scanning a target or requiring nmap.
        arguments = ['two words', "quoted'argument", '$(printf expanded)', '; exit 0']
        command = [sys.executable, '-c',
                   'import json, sys; print(json.dumps(sys.argv[1:])); sys.exit(7)', *arguments]
        result = self.executors['kali'](command, timeout=5).execute()
        self.assertIs(result['success'], False)
        self.assertIs(result['timed_out'], False)
        self.assertEqual(result['return_code'], 7)
        self.assertEqual(json.loads(result['stdout']), arguments)
        self.assertEqual(result['stderr'], '')

    def test_kali_tool_argv_timeout_retains_partial_output_and_failure(self):
        command = [sys.executable, '-u', '-c',
                   "import time; print('argv-partial-evidence'); time.sleep(30)"]
        result = self.executors['kali'](command, timeout=0.3).execute()
        self.assertIs(result['success'], False)
        self.assertIs(result['timed_out'], True)
        self.assertIs(result['partial_results'], True)
        self.assertEqual(result['stdout'], 'argv-partial-evidence\n')


if __name__ == '__main__':
    unittest.main()
