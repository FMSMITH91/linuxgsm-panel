"""This process's LISTEN sockets from /proc/net/tcp and tcp6, read once per report (R19, R38).
Owner: builder B3.

listening() -> list of {"addr": str, "port": int, "family": 4|6, "inode": int} owned by this process,
    or raises OSError (the caller prints 'could not be read').
"""


def listening():
    """Not implemented yet."""
    raise NotImplementedError
