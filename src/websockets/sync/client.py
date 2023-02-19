from __future__ import annotations

import socket
import ssl
import threading
from typing import Any, Optional, Sequence, Type

from ..client import ClientProtocol
from ..datastructures import HeadersLike
from ..extensions.base import ClientExtensionFactory
from ..extensions.permessage_deflate import enable_client_permessage_deflate
from ..headers import validate_subprotocols
from ..http import USER_AGENT
from ..http11 import Response
from ..protocol import CONNECTING, OPEN, Event
from ..typing import LoggerLike, Origin, Subprotocol
from ..uri import parse_uri
from .connection import Connection
from .utils import Deadline


__all__ = ["connect", "unix_connect", "ClientConnection"]


class ClientConnection(Connection):
    """
    Threaded implementation of a WebSocket client connection.

    :class:`ClientConnection` provides :meth:`recv` and :meth:`send` methods for
    receiving and sending messages.

    It supports iteration to receive messages::

        for message in websocket:
            process(message)

    The iterator exits normally when the connection is closed with close code
    1000 (OK) or 1001 (going away). It raises a
    :exc:`~websockets.exceptions.ConnectionClosedError` when the connection is
    closed with any other code.

    The ``close_timeout`` parameter defines a maximum wait time for completing
    the closing handshake and terminating the TCP connection.

    Args:
        socket: socket connected to the WebSocket server.
        protocol: Sans-I/O connection.
        close_timeout: timeout for closing the connection in seconds.

    """

    def __init__(
        self,
        socket: socket.socket,
        protocol: ClientProtocol,
        *,
        close_timeout: Optional[float] = None,
    ) -> None:
        self.protocol: ClientProtocol
        self.response_rcvd = threading.Event()
        super().__init__(
            socket,
            protocol,
            close_timeout=close_timeout,
        )

    def handshake(
        self,
        additional_headers: Optional[HeadersLike] = None,
        user_agent_header: Optional[str] = USER_AGENT,
        timeout: Optional[float] = None,
    ) -> None:
        """
        Perform the opening handshake.

        """
        with self.send_context(expected_state=CONNECTING):
            self.request = self.protocol.connect()
            if additional_headers is not None:
                self.request.headers.update(additional_headers)
            if user_agent_header is not None:
                self.request.headers["User-Agent"] = user_agent_header
            self.protocol.send_request(self.request)

        if not self.response_rcvd.wait(timeout):
            self.socket.close()
            self.recv_events_thread.join()
            raise TimeoutError("timed out during handshake")

        if self.response is None:
            self.socket.close()
            self.recv_events_thread.join()
            raise ConnectionError("connection closed during handshake")

        if self.protocol.state is not OPEN:
            self.recv_events_thread.join(self.close_timeout)
            self.socket.close()
            self.recv_events_thread.join()

        if self.protocol.handshake_exc is not None:
            raise self.protocol.handshake_exc

    def process_event(self, event: Event) -> None:
        """
        Process one incoming event.

        """
        # First event - handshake response.
        if self.response is None:
            assert isinstance(event, Response)
            self.response = event
            self.response_rcvd.set()
        # Later events - frames.
        else:
            super().process_event(event)

    def recv_events(self) -> None:
        """
        Read incoming data from the socket and process events.

        """
        try:
            super().recv_events()
        finally:
            # If the connection is closed during the handshake, unblock it.
            self.response_rcvd.set()


def connect(
    uri: str,
    *,
    # TCP/TLS — unix and path are only for unix_connect()
    sock: Optional[socket.socket] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_hostname: Optional[str] = None,
    unix: bool = False,
    path: Optional[str] = None,
    # WebSocket
    origin: Optional[Origin] = None,
    extensions: Optional[Sequence[ClientExtensionFactory]] = None,
    subprotocols: Optional[Sequence[Subprotocol]] = None,
    additional_headers: Optional[HeadersLike] = None,
    user_agent_header: Optional[str] = USER_AGENT,
    compression: Optional[str] = "deflate",
    # Timeouts
    open_timeout: Optional[float] = None,
    close_timeout: Optional[float] = None,
    # Limits
    max_size: Optional[int] = 2**20,
    # Logging
    logger: Optional[LoggerLike] = None,
    # Escape hatch for advanced customization (undocumented)
    create_connection: Optional[Type[ClientConnection]] = None,
) -> ClientConnection:

    # Process parameters

    wsuri = parse_uri(uri)
    if not wsuri.secure and ssl_context is not None:
        raise TypeError("ssl_context argument is incompatible with a ws:// URI")

    if unix:
        if path is None and sock is None:
            raise TypeError("missing path argument")
        elif path is not None and sock is not None:
            raise TypeError("path and sock arguments are incompatible")
    else:
        assert path is None  # private argument, only set by unix_connect()

    if subprotocols is not None:
        validate_subprotocols(subprotocols)

    if compression == "deflate":
        extensions = enable_client_permessage_deflate(extensions)
    elif compression is not None:
        raise ValueError(f"unsupported compression: {compression}")

    # Calculate timeouts on the TCP, TLS, and WebSocket handshakes.
    # The TCP and TLS timeouts must be set on the socket, then removed
    # to avoid conflicting with the WebSocket timeout in handshake().
    deadline = Deadline(open_timeout)

    if create_connection is None:
        create_connection = ClientConnection

    # Connect socket

    # TODO - close socket if exception happens after creating it

    if sock is None:
        if unix:
            assert path is not None  # validated above -- this is for mpypy
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(deadline.timeout())
            sock.connect(path)
            sock.settimeout(None)
        else:
            sock = socket.create_connection(
                (wsuri.host, wsuri.port),
                deadline.timeout(),
            )
            sock.settimeout(None)

    # Disable Nagle algorithm

    if not unix:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

    # Initialize TLS wrapper and perform TLS handshake

    if wsuri.secure:
        if ssl_context is None:
            ssl_context = ssl.create_default_context()
        if server_hostname is None:
            server_hostname = wsuri.host
        sock.settimeout(deadline.timeout())
        sock = ssl_context.wrap_socket(sock, server_hostname=server_hostname)
        sock.settimeout(None)

    # Initialize WebSocket connection

    protocol = ClientProtocol(
        wsuri,
        origin=origin,
        extensions=extensions,
        subprotocols=subprotocols,
        state=CONNECTING,
        max_size=max_size,
        logger=logger,
    )

    # Initialize WebSocket protocol

    connection = create_connection(
        sock,
        protocol,
        close_timeout=close_timeout,
    )
    connection.handshake(
        additional_headers,
        user_agent_header,
        deadline.timeout(),
    )
    return connection


def unix_connect(
    path: Optional[str] = None,
    uri: Optional[str] = None,
    **kwargs: Any,
) -> ClientConnection:
    """
    Similar to :func:`connect`, but for connecting to a Unix socket.

    This function is only available on Unix.

    It's mainly useful for debugging servers listening on Unix sockets.

    Args:
        path: file system path to the Unix socket.
        uri: URI of the WebSocket server; the host is used in the TLS
            handshake for secure connections and in the ``Host`` header.

    """
    if uri is None:
        if kwargs.get("ssl_context") is None:
            uri = "ws://localhost/"
        else:
            uri = "wss://localhost/"
    return connect(uri=uri, unix=True, path=path, **kwargs)
