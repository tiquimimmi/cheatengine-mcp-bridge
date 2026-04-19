#!/usr/bin/env python3

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import textwrap
import time
import unittest

try:
    from transport_config import DEFAULT_TCP_PORT, PIPE_NAME, WIRE_PROTOCOL_VERSION, parse_bridge_uri
except ImportError:
    from MCP_Server.transport_config import DEFAULT_TCP_PORT, PIPE_NAME, WIRE_PROTOCOL_VERSION, parse_bridge_uri


class ParseBridgeUriTests(unittest.TestCase):
    def test_constants_stay_in_sync(self):
        self.assertEqual(WIRE_PROTOCOL_VERSION, 99)
        self.assertEqual(PIPE_NAME, r"\\.\pipe\CE_MCP_Bridge_v99")
        self.assertEqual(DEFAULT_TCP_PORT, 28015)

    def test_empty_uri_defaults_to_pipe_on_windows(self):
        self.assertEqual(parse_bridge_uri("", has_win32=True), ("pipe", None, None))

    def test_empty_uri_defaults_to_tcp_on_non_windows(self):
        self.assertEqual(
            parse_bridge_uri("", has_win32=False),
            ("tcp", "127.0.0.1", DEFAULT_TCP_PORT),
        )

    def test_pipe_uri_parses(self):
        self.assertEqual(parse_bridge_uri("pipe", has_win32=True), ("pipe", None, None))

    def test_tcp_uri_with_host_and_port(self):
        self.assertEqual(
            parse_bridge_uri("tcp:192.168.1.10:31337", has_win32=True),
            ("tcp", "192.168.1.10", 31337),
        )

    def test_tcp_uri_with_port_only(self):
        self.assertEqual(
            parse_bridge_uri("tcp::31337", has_win32=True),
            ("tcp", "127.0.0.1", 31337),
        )

    def test_tcp_uri_with_host_only(self):
        self.assertEqual(
            parse_bridge_uri("tcp:ce-box", has_win32=True),
            ("tcp", "ce-box", DEFAULT_TCP_PORT),
        )

    def test_invalid_uri_raises(self):
        with self.assertRaises(ValueError):
            parse_bridge_uri("udp:127.0.0.1:28015", has_win32=True)

    def test_port_out_of_range_high(self):
        with self.assertRaises(ValueError) as ctx:
            parse_bridge_uri("tcp:host:70000", has_win32=True)
        self.assertIn("out of range", str(ctx.exception).lower())

    def test_port_out_of_range_zero(self):
        with self.assertRaises(ValueError):
            parse_bridge_uri("tcp:host:0", has_win32=True)

    def test_port_negative(self):
        with self.assertRaises(ValueError):
            parse_bridge_uri("tcp:host:-1", has_win32=True)

    def test_port_non_numeric(self):
        with self.assertRaises(ValueError) as ctx:
            parse_bridge_uri("tcp:host:abc", has_win32=True)
        self.assertIn("must be an integer", str(ctx.exception).lower())

    def test_port_boundary_valid_low(self):
        self.assertEqual(
            parse_bridge_uri("tcp:host:1", has_win32=True),
            ("tcp", "host", 1),
        )

    def test_port_boundary_valid_high(self):
        self.assertEqual(
            parse_bridge_uri("tcp:host:65535", has_win32=True),
            ("tcp", "host", 65535),
        )


class CreateBridgeClientTests(unittest.TestCase):
    """Test the runtime factory and client classes (not just URI parsing)."""

    def _run_import_only_subprocess(self, *, ce_mcp_uri: str):
        repo_root = os.path.dirname(os.path.dirname(__file__))
        script = textwrap.dedent(
            f"""
            import builtins
            import sys

            sys.path.insert(0, {repo_root!r})
            sys.platform = 'linux'

            blocked_modules = {{'win32file', 'win32pipe', 'win32con', 'pywintypes'}}
            original_import = builtins.__import__

            def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
                if name in blocked_modules:
                    raise ImportError(f'blocked {{name}}')
                return original_import(name, globals, locals, fromlist, level)

            builtins.__import__ = blocked_import
            import MCP_Server.mcp_cheatengine
            """
        )
        env = os.environ.copy()
        env["CE_MCP_URI"] = ce_mcp_uri
        return subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            cwd=repo_root,
            env=env,
            text=True,
        )

    def test_pipe_on_non_windows_fails_during_module_import(self):
        """Forced pipe mode without pywin32 should fail on import, matching production."""
        result = self._run_import_only_subprocess(ce_mcp_uri="pipe")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "RuntimeError: Named Pipe transport requires Windows and pywin32.",
            result.stderr,
        )
        self.assertIn("ce_client = create_bridge_client()", result.stderr)


class TCPBridgeClientNegativeTests(unittest.TestCase):
    """Test TCP client failure paths using real sockets and mock servers."""

    def _get_tcp_client_class(self):
        import sys
        import io
        orig_stdin = sys.stdin
        if not hasattr(sys.stdin, '_original_fileno'):
            try:
                sys.stdin.fileno()
            except (io.UnsupportedOperation, AttributeError):
                sys.stdin = open(os.devnull, 'r')
        try:
            try:
                from mcp_cheatengine import TCPBridgeClient
            except ImportError:
                from MCP_Server.mcp_cheatengine import TCPBridgeClient
        finally:
            sys.stdin = orig_stdin
        return TCPBridgeClient

    def _find_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_tcp_wrong_port_raises_connection_error(self):
        """Connecting to a port with no listener should raise ConnectionError."""
        TCPBridgeClient = self._get_tcp_client_class()
        free_port = self._find_free_port()
        # Port is freed now, so nothing is listening
        client = TCPBridgeClient("127.0.0.1", free_port)
        client.timeout_seconds = 3  # fast timeout for test
        with self.assertRaises((ConnectionError, OSError)):
            client.send_command("ping")

    def test_tcp_version_mismatch_raises_connection_error(self):
        """Server responding with wrong protocol_version should raise ConnectionError."""
        TCPBridgeClient = self._get_tcp_client_class()
        port = self._find_free_port()
        server_ready = threading.Event()
        server_done = threading.Event()

        def _send_wrong_version(conn):
            """Read one ping request, respond with wrong protocol_version."""
            header = conn.recv(4)
            if len(header) < 4:
                return
            length = struct.unpack('<I', header)[0]
            body = conn.recv(length)
            req = json.loads(body.decode('utf-8'))
            response = {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {
                    "success": True,
                    "version": "12.0.0",
                    "protocol_version": 1,  # wrong version
                    "transport": "tcp",
                    "timestamp": int(time.time()),
                    "process_id": 0,
                    "message": "test"
                }
            }
            resp_bytes = json.dumps(response).encode('utf-8')
            conn.sendall(struct.pack('<I', len(resp_bytes)) + resp_bytes)

        def mock_server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(2)
            srv.settimeout(10)
            server_ready.set()
            # Handle both the initial attempt and the retry from send_command
            for _ in range(2):
                try:
                    conn, _ = srv.accept()
                    _send_wrong_version(conn)
                    conn.close()
                except socket.timeout:
                    break
            srv.close()
            server_done.set()

        t = threading.Thread(target=mock_server, daemon=True)
        t.start()
        server_ready.wait(timeout=5)

        client = TCPBridgeClient("127.0.0.1", port)
        client.timeout_seconds = 5
        with self.assertRaises(ConnectionError) as ctx:
            client.send_command("ping")
        self.assertIn("version mismatch", str(ctx.exception).lower())
        server_done.wait(timeout=5)

    def test_tcp_unresponsive_server_times_out(self):
        """Server that accepts but never responds should trigger timeout."""
        TCPBridgeClient = self._get_tcp_client_class()
        port = self._find_free_port()
        server_ready = threading.Event()
        server_done = threading.Event()
        retry_connection_seen = threading.Event()
        release_connections = threading.Event()
        accepted_connections = []
        server_errors = []

        def mock_server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(2)
            srv.settimeout(10)
            server_ready.set()
            try:
                while len(accepted_connections) < 2:
                    conn, _ = srv.accept()
                    accepted_connections.append(conn)
                    if len(accepted_connections) == 2:
                        retry_connection_seen.set()
                release_connections.wait(timeout=10)
            except Exception as exc:
                server_errors.append(exc)
            finally:
                for conn in accepted_connections:
                    conn.close()
                srv.close()
                server_done.set()

        t = threading.Thread(target=mock_server, daemon=True)
        t.start()
        server_ready.wait(timeout=5)

        client = TCPBridgeClient("127.0.0.1", port)
        client.timeout_seconds = 1

        try:
            with self.assertRaises(TimeoutError) as ctx:
                client.send_command("ping")
            self.assertIn("Command 'ping' timed out after 1s", str(ctx.exception))
            self.assertTrue(
                retry_connection_seen.wait(timeout=1),
                "Expected send_command() to retry after the first timeout.",
            )
            self.assertEqual(len(accepted_connections), 2)
            self.assertFalse(server_errors, f"Mock server error(s): {server_errors}")
        finally:
            release_connections.set()
            server_done.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
