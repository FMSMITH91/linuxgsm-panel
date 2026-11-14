"""A command's stdin given in pieces: what the transports in panel.ops.ssh_manager._core write.

Its own module so the transport module stays within its size; _core re-exports these names.
"""


class StdinChunks:
    """A command's stdin given as chunks of bytes, written one after another (run_command's stdin_text).

    For a large input (a backup upload's piece, base64'd as it goes): it is never held whole, and no
    write is handed more than one chunk. Written whole, a 5.6 MB stdin left the panel's resident size
    some 100 MB higher after a hundred pieces (measured on the local transport): every partial
    write of the pipe copied what was left.
    """

    __slots__ = ("_chunks",)

    def __init__(self, chunks):
        """Keep the iterable of bytes chunks; it is read once, by the transport."""
        self._chunks = chunks

    def __iter__(self):
        """The chunks, in order."""
        return iter(self._chunks)

    def __bool__(self):
        """Always true: a stdin to write, even before its chunks are read."""
        return True


STDIN_SLICE = 65536


def stdin_bytes(stdin_text):
    """What the transports write: text as UTF-8, StdinChunks (and bytes) as they are, None for none."""
    return stdin_text.encode("utf-8") if isinstance(stdin_text, str) else stdin_text


def stdin_pieces(data):
    """The writes `data` is made of: its chunks, or bytes in slices no larger than STDIN_SLICE."""
    if isinstance(data, StdinChunks):
        return data
    view = memoryview(data)
    return (view[i:i + STDIN_SLICE] for i in range(0, len(view), STDIN_SLICE))


def write_channel_stdin(stdin, stdin_text):
    """Write `stdin_text` to a paramiko exec channel's stdin file and flush it; nothing for None.

    StdinChunks go one chunk at a time; anything else is written whole, as it always was (paramiko's
    own file splits it into packets without copying).
    """
    if stdin_text is None:
        return
    for piece in (stdin_text if isinstance(stdin_text, StdinChunks) else (stdin_text,)):
        stdin.write(piece)
    stdin.flush()
