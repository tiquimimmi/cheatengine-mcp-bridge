"""Shared transport constants and CE_MCP_URI parsing."""

WIRE_PROTOCOL_VERSION = 99
PIPE_NAME = r"\\.\pipe\CE_MCP_Bridge_v" + str(WIRE_PROTOCOL_VERSION)
DEFAULT_TCP_PORT = 28015
DEFAULT_TCP_HOST = "127.0.0.1"


def parse_bridge_uri(uri: str, has_win32: bool):
    """Parse CE_MCP_URI into (transport, host, port).

    Supported values:
    - "" / unset -> pipe on Windows, localhost TCP elsewhere
    - "pipe"
    - "tcp:HOST:PORT"
    - "tcp::PORT"
    - "tcp:HOST"
    """
    uri = (uri or "").strip()
    if not uri:
        if has_win32:
            return "pipe", None, None
        return "tcp", DEFAULT_TCP_HOST, DEFAULT_TCP_PORT

    if uri == "pipe":
        return "pipe", None, None

    if uri.startswith("tcp:"):
        parts = uri[4:]
        host, port = DEFAULT_TCP_HOST, DEFAULT_TCP_PORT
        if ":" in parts:
            parsed_host, parsed_port = parts.rsplit(":", 1)
            if parsed_host:
                host = parsed_host
            if parsed_port:
                try:
                    port = int(parsed_port)
                except ValueError:
                    raise ValueError(
                        f"Invalid port in CE_MCP_URI: {parsed_port!r}. Must be an integer."
                    )
                if not (1 <= port <= 65535):
                    raise ValueError(
                        f"Port out of range in CE_MCP_URI: {port}. Must be 1-65535."
                    )
        elif parts:
            host = parts
        return "tcp", host, port

    raise ValueError(
        f"Invalid CE_MCP_URI: {uri!r}. Expected 'pipe' or 'tcp:HOST:PORT'."
    )
