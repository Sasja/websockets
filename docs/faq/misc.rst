Miscellaneous
=============

.. currentmodule:: websockets

Why do I get the error: ``module 'websockets' has no attribute '...'``?
.......................................................................

Often, this is because you created a script called ``websockets.py`` in your
current working directory. Then ``import websockets`` imports this module
instead of the websockets library.

.. _real-import-paths:

Why does my IDE fail to show documentation for websockets APIs?
...............................................................

You are probably using the convenience imports e.g.::

    import websockets

    websockets.connect(...)
    websockets.serve(...)

This is incompatible with static code analysis. It may break auto-completion and
contextual documentation in IDEs, type checking with mypy_, etc.

.. _mypy: https://github.com/python/mypy

Instead, use the real import paths e.g.::

    import websockets.client
    import websockets.server

    websockets.client.connect(...)
    websockets.server.serve(...)

Why is the default implementation located in ``websockets.legacy``?
...................................................................

This is an artifact of websockets' history. For its first eight years, only the
:mod:`asyncio`-based implementation existed. Then, the Sans-I/O implementation
was added. Moving the code in a ``legacy`` submodule eased this refactoring and
optimized maintainability.

All public APIs were kept at their original locations. ``websockets.legacy``
isn't a public API. It's only visible in the source code and in stack traces.
There is no intent to deprecate this implementation — at least until a superior
alternative exists.

Why is websockets slower than another library in my benchmark?
..............................................................

Not all libraries are as feature-complete as websockets. For a fair benchmark,
you should disable features that the other library doesn't provide. Typically,
you may need to disable:

* Compression: set ``compression=None``
* Keepalive: set ``ping_interval=None``
* UTF-8 decoding: send ``bytes`` rather than ``str``

If websockets is still slower than another Python library, please file a bug.

Can I use websockets without ``async`` and ``await``?
.....................................................

No, there is no convenient way to do this. You should use another library.

Are there ``onopen``, ``onmessage``, ``onerror``, and ``onclose`` callbacks?
............................................................................

No, there aren't.

websockets provides high-level, coroutine-based APIs. Compared to callbacks,
coroutines make it easier to manage control flow in concurrent code.

If you prefer callback-based APIs, you should use another library.
