from __future__ import annotations

import logging
import socket
import ssl
import threading
from types import TracebackType
from typing import Any, Callable, Optional, Sequence, Tuple, Type, Union

from ..extensions.base import ServerExtensionFactory
from ..extensions.permessage_deflate import enable_server_permessage_deflate
from ..headers import validate_subprotocols
from ..http import USER_AGENT
from ..http11 import Request, Response
from ..protocol import CONNECTING, OPEN, Event
from ..server import ServerProtocol
from ..typing import LoggerLike, Origin, Subprotocol
from .compatibility import socket_create_server
from .connection import Connection
from .utils import Deadline


__all__ = ["serve", "unix_serve", "ServerConnection", "WebSocketServer"]


class ServerConnection(Connection):
    """
    Threaded implementation of a WebSocket server connection.

    :class:`ServerConnection` provides :meth:`recv` and :meth:`send` methods for
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
        protocol: ServerProtocol,
        *,
        close_timeout: Optional[float] = None,
    ) -> None:
        self.protocol: ServerProtocol
        self.request_rcvd = threading.Event()
        super().__init__(
            socket,
            protocol,
            close_timeout=close_timeout,
        )

    def handshake(
        self,
        process_request: Optional[ProcessRequest] = None,
        process_response: Optional[ProcessResponse] = None,
        server_header: Optional[str] = USER_AGENT,
        timeout: Optional[float] = None,
    ) -> None:
        """
        Perform the opening handshake.

        """
        if not self.request_rcvd.wait(timeout):
            self.socket.close()
            self.recv_events_thread.join()
            raise TimeoutError("timed out during handshake")

        if self.request is None:
            self.socket.close()
            self.recv_events_thread.join()
            raise ConnectionError("connection closed during handshake")

        with self.send_context(expected_state=CONNECTING):
            response = None

            if process_request is not None:
                response = process_request(self, self.request)

            if response is None:
                self.response = self.protocol.accept(self.request)
            else:
                self.response = response

            if process_response is not None:
                process_response(self, self.request, self.response)

            if server_header is not None:
                self.response.headers["Server"] = server_header

            self.protocol.send_response(self.response)

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
        # First event - handshake request.
        if self.request is None:
            assert isinstance(event, Request)
            self.request = event
            self.request_rcvd.set()
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
            self.request_rcvd.set()


class WebSocketServer:
    """
    WebSocket server returned by :func:`serve`.

    This class provides the same interface as :class:`~socketserver.BaseServer`,
    notably the :meth:`~socketserver.BaseServer.shutdown` method.

    Args:
        socket: server socket listening for new connections.
        handler: callable for each connection; receives the socket
            and address returned by :meth:`~socket.socket.accept`.
        logger: logger for this server;
            defaults to ``logging.getLogger("websockets.server")``; see the
            :doc:`logging guide <../../topics/logging>` for details.

    """

    def __init__(
        self,
        socket: socket.socket,
        handler: Callable[[socket.socket, Union[Tuple[str, int], str]], None],
        logger: Optional[LoggerLike] = None,
    ):
        self.socket = socket
        self.handler = handler
        if logger is None:
            logger = logging.getLogger("websockets.server")
        self.logger = logger

    def serve_forever(self) -> None:
        """
        See :meth:`socketserver.BaseServer.serve_forever`.

        Typical use::

            with serve(...) as server:
                # this method doesn't return
                # calling shutdown() from another thread stops the server
                server.serve_forever()

        """
        while True:
            try:
                sock, addr = self.socket.accept()
            except OSError:
                break

            thread = threading.Thread(target=self.handler, args=(sock, addr, self))
            thread.start()

    def shutdown(self) -> None:
        """
        See :meth:`socketserver.BaseServer.shutdown`.

        """
        self.socket.close()

    def fileno(self) -> int:
        """
        See :meth:`socketserver.BaseServer.fileno`.

        """
        return self.socket.fileno()

    def server_close(self) -> None:
        self.socket.close()

    def __enter__(self) -> WebSocketServer:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.server_close()


def serve(
    handler: Callable[[ServerConnection], Any],
    host: Optional[str] = None,
    port: Optional[int] = None,
    *,
    # TCP/TLS — unix and path are only for unix_serve()
    sock: Optional[socket.socket] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    unix: bool = False,
    path: Optional[str] = None,
    # WebSocket
    origins: Optional[Sequence[Optional[Origin]]] = None,
    extensions: Optional[Sequence[ServerExtensionFactory]] = None,
    subprotocols: Optional[Sequence[Subprotocol]] = None,
    select_subprotocol: Optional[SelectSubprotocol] = None,
    process_request: Optional[ProcessRequest] = None,
    process_response: Optional[ProcessResponse] = None,
    server_header: Optional[str] = USER_AGENT,
    compression: Optional[str] = "deflate",
    # Timeouts
    open_timeout: Optional[float] = 10,
    close_timeout: Optional[float] = 10,
    # Limits
    max_size: Optional[int] = 2**20,
    # Logging
    logger: Optional[LoggerLike] = None,
    # Escape hatch for advanced customization (undocumented)
    create_connection: Optional[Type[ServerConnection]] = None,
) -> WebSocketServer:
    """
    Start a WebSocket server listening on ``host`` and ``port``.

    Whenever a client connects, the server creates a :class:`ServerConnection`,
    performs the opening handshake, and delegates to the ``handler``.

    The handler receives the :class:`ServerConnection` and uses it to send and
    receive messages.

    Once the handler completes, either normally or with an exception, the server
    performs the closing handshake and closes the connection.

    Args:
        handler: connection handler; it receives the WebSocket connection,
            which is a :class:`ServerConnection`, in argument.
        host: network interfaces the server is bound to;
            see :func:`~socket.create_server` for details.
        port: TCP port the server listens on;
            see :func:`~socket.create_server` for details.
        sock: preexisting TCP socket; replaces ``host`` and ``port``.
        ssl_context: configuration for enabling TLS on accepted connections.
        origins: acceptable values of the ``Origin`` header; include
            :obj:`None` in the list if the lack of an origin is acceptable.
            This is useful for defending against Cross-Site WebSocket
            Hijacking attacks.
        extensions: list of supported extensions, in order in which they
            should be tried.
        subprotocols: list of supported subprotocols, in order of decreasing
            preference.
        select_subprotocol: select a subprotocol supported by the client;
            TODO.
        process_request:
            intercept HTTP request during the opening handshake; TODO.
        process_request:
            intercept HTTP response during the opening handshake; TODO.
        server_header: value of  the ``Server`` response header;
            defaults to ``"Python/x.y.z websockets/X.Y"``;
            :obj:`None` removes the header.
        compression: shortcut that enables the "permessage-deflate" extension
            by default; may be set to :obj:`None` to disable compression; see
            the :doc:`compression guide <../../topics/compression>` for details.
        open_timeout: TODO
        close_timeout: TODO
        max_size: TODO
        logger: logger for this server;
            defaults to ``logging.getLogger("websockets.server")``; see the
            :doc:`logging guide <../../topics/logging>` for details.
        create_connection: TODO


    See :class:`~websockets.legacy.protocol.WebSocketCommonProtocol` for the
    documentation of ``ping_interval``, ``ping_timeout``, ``close_timeout``,
    ``max_size``, ``max_queue``, ``read_limit``, and ``write_limit``.

    Any other keyword arguments are passed the event loop's
    :meth:`~asyncio.loop.create_server` method.

    For example:

    * You can set ``ssl`` to a :class:`~ssl.SSLContext` to enable TLS.

    * You can set ``sock`` to a :obj:`~socket.socket` that you created outside
      of websockets.

    Returns:
        WebSocketServer: WebSocket server.


    """

    # Process parameters

    if subprotocols is not None:
        validate_subprotocols(subprotocols)

    if compression == "deflate":
        extensions = enable_server_permessage_deflate(extensions)
    elif compression is not None:
        raise ValueError(f"unsupported compression: {compression}")

    if create_connection is None:
        create_connection = ServerConnection

    # Bind socket and listen

    if sock is None:
        # TODO - pass unknown arguments to create_server?
        if unix:
            if path is None:
                raise TypeError("missing path argument")
            sock = socket_create_server(path, family=socket.AF_UNIX)
        else:
            sock = socket_create_server((host, port))
    else:
        if path is not None:
            raise TypeError("path and sock arguments are incompatible")

    # Initialize TLS wrapper

    if ssl_context is not None:
        sock = ssl_context.wrap_socket(
            sock, server_side=True, do_handshake_on_connect=False
        )

    # Define request handler

    # TODO some arguments here are unused
    def handler(sock: socket.socket, addr: Any, server: WebSocketServer) -> None:

        # Calculate timeouts on the TLS and WebSocket handshakes.
        # The TLS timeout must be set on the socket, then removed
        # to avoid conflicting with the WebSocket timeout in handshake().
        deadline = Deadline(open_timeout)

        # Disable Nagle algorithm

        if not unix:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

        # Perform TLS handshake

        if ssl_context is not None:
            try:
                sock.settimeout(deadline.timeout())
                assert isinstance(sock, ssl.SSLSocket)  # mypy cannot figure this out
                sock.do_handshake()
                sock.settimeout(None)
            except Exception:
                # TODO: log exceptions
                # TODO: more broadly, review error handling logic to close
                # socket in ALL exit paths (even those not suppposed to crash)
                sock.close()
                return

        # Create a closure so that select_subprotocol has access to self.

        protocol_select_subprotocol: Optional[Callable[
                [ServerProtocol, Sequence[Subprotocol]],
                Optional[Subprotocol],
            ]] = None
        if select_subprotocol is not None:

            def protocol_select_subprotocol(
                protocol: ServerProtocol,
                subprotocols: Sequence[Subprotocol],
            ) -> Optional[Subprotocol]:
                # mypy doesn't know that select_subprotocol is immutable.
                assert select_subprotocol is not None
                # Ensure this function is only used in the intended context.
                assert protocol is connection.protocol
                return select_subprotocol(connection, subprotocols)

        # Initialize WebSocket connection

        protocol = ServerProtocol(
            origins=origins,
            extensions=extensions,
            subprotocols=subprotocols,
            select_subprotocol=protocol_select_subprotocol,
            state=CONNECTING,
            max_size=max_size,
            logger=logger,
        )

        # Initialize WebSocket protocol

        assert create_connection is not None  # help mypy
        connection = create_connection(
            sock,
            protocol,
            close_timeout=close_timeout,
        )

        try:
            connection.handshake(
                process_request,
                process_response,
                server_header,
                deadline.timeout(),
            )
        except Exception:
            # TODO: log exceptions
            pass
        else:
            # TODO should we reset timeouts here like in the client?
            # If status code isn't 101, handshake() raises handshake_exc.
            assert connection.response is not None
            assert connection.response.status_code == 101
            handler(connection)
        finally:
            connection.close()

    # Initialize server

    # TODO fix typing here
    return WebSocketServer(sock, handler, logger)  # type: ignore


def unix_serve(
    handler: Callable[[ServerConnection], Any],
    path: Optional[str] = None,
    **kwargs: Any,
) -> WebSocketServer:
    """
    Similar to :func:`serve`, but for listening on Unix sockets.

    This function is only available on Unix.

    It's useful for deploying a server behind a reverse proxy such as nginx.

    :param path: file system path to the Unix socket

    """
    return serve(handler, path=path, unix=True, **kwargs)


ProcessRequest = Callable[
    [ServerConnection, Request],
    Optional[Response],
]


ProcessResponse = Callable[
    [ServerConnection, Request, Response],
    None,
]


SelectSubprotocol = Callable[
    [ServerConnection, Sequence[Subprotocol], Sequence[Subprotocol]],
    Optional[Subprotocol],
]
