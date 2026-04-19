#!/usr/bin/env python3
"""
TCP-to-FIFO proxy for CE MCP Bridge on macOS.

Bridges TCP connections from a remote MCP client to the CE Lua bridge
via POSIX FIFOs (named pipes). Use this when CE's Lua has dynamic
library loading disabled and LuaSocket cannot be loaded.

Usage:
    python3 tcp_fifo_proxy.py [--port 28015] [--host 0.0.0.0]

The proxy creates two FIFOs:
    /tmp/ce_mcp_request   - proxy writes requests, Lua reads
    /tmp/ce_mcp_response  - Lua writes responses, proxy reads

The Lua bridge must be configured with TRANSPORT_MODE = "fifo".
Start this proxy BEFORE loading the Lua script in CE.
"""

import argparse
import os
import signal
import socket
import struct
import sys
import time

REQUEST_FIFO = "/tmp/ce_mcp_request"
RESPONSE_FIFO = "/tmp/ce_mcp_response"
MAX_MESSAGE_SIZE = 32 * 1024 * 1024


def create_fifos():
    """Create FIFO files if they don't exist."""
    for path in (REQUEST_FIFO, RESPONSE_FIFO):
        if os.path.exists(path):
            if not stat_is_fifo(path):
                os.remove(path)
                os.mkfifo(path)
                print(f"Recreated FIFO: {path}")
            else:
                print(f"FIFO exists: {path}")
        else:
            os.mkfifo(path)
            print(f"Created FIFO: {path}")


def stat_is_fifo(path):
    import stat
    return stat.S_ISFIFO(os.stat(path).st_mode)


def cleanup_fifos():
    for path in (REQUEST_FIFO, RESPONSE_FIFO):
        try:
            os.remove(path)
        except OSError:
            pass


def read_tcp_message(sock):
    """Read a length-prefixed message from TCP socket."""
    header = recv_exact(sock, 4)
    if not header:
        return None
    length = struct.unpack('<I', header)[0]
    if length <= 0 or length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Invalid message length: {length}")
    body = recv_exact(sock, length)
    if not body:
        return None
    return header + body  # pass through the full framed message


def recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def write_to_fifo(data):
    """Write a framed message to the request FIFO."""
    # Opening a FIFO for writing blocks until a reader opens it
    with open(REQUEST_FIFO, "wb") as f:
        f.write(data)
        f.flush()


def read_from_fifo():
    """Read a framed response from the response FIFO."""
    # Opening a FIFO for reading blocks until a writer opens it
    with open(RESPONSE_FIFO, "rb") as f:
        header = f.read(4)
        if not header or len(header) < 4:
            return None
        length = struct.unpack('<I', header)[0]
        if length <= 0 or length > MAX_MESSAGE_SIZE:
            raise ValueError(f"Invalid response length: {length}")
        body = f.read(length)
        if not body or len(body) < length:
            return None
        return header + body


def handle_client(client_sock, addr):
    """Handle one TCP client connection."""
    print(f"TCP client connected: {addr}")
    client_sock.settimeout(60)

    try:
        while True:
            # Read request from TCP
            request = read_tcp_message(client_sock)
            if not request:
                print(f"Client {addr} disconnected")
                break

            # Forward to CE via request FIFO
            write_to_fifo(request)

            # Read response from CE via response FIFO
            response = read_from_fifo()
            if not response:
                print("ERROR: No response from CE (FIFO read failed)")
                break

            # Send response back to TCP client
            client_sock.sendall(response)

    except (ConnectionError, TimeoutError, OSError) as e:
        print(f"Client {addr} error: {e}")
    finally:
        client_sock.close()
        print(f"Client {addr} session ended")


def main():
    parser = argparse.ArgumentParser(description="TCP-to-FIFO proxy for CE MCP Bridge")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=28015, help="TCP port (default: 28015)")
    args = parser.parse_args()

    # Handle clean shutdown
    def signal_handler(sig, frame):
        print("\nShutting down proxy...")
        cleanup_fifos()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    create_fifos()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)

    print(f"TCP-to-FIFO proxy listening on tcp://{args.host}:{args.port}")
    print(f"Request FIFO:  {REQUEST_FIFO}")
    print(f"Response FIFO: {RESPONSE_FIFO}")
    print("Waiting for CE Lua script to connect to FIFOs...")
    print("(Load ce_mcp_bridge.lua in CE with TRANSPORT_MODE = \"fifo\")")

    try:
        while True:
            client_sock, addr = server.accept()
            handle_client(client_sock, addr)
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        cleanup_fifos()
        print("Proxy stopped")


if __name__ == "__main__":
    main()
