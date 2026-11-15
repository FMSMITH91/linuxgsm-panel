"""Paramiko, imported the first time something uses it rather than when the panel starts.

paramiko and the cryptography it loads are ~12 MB of the panel's resident memory (measured on the
test host: +12.0 MB RSS for `import paramiko` on top of everything else the panel imports), and
only a host reached over direct SSH (key or password) ever uses it: the panel's own host runs its
commands locally and a Tailscale host through the `ssh` command. A panel that manages only its own
host, or only Tailscale hosts, now never loads it.

A module's `paramiko = _lazy.LazyModule("paramiko")` stands for the module, each module holding its
own (so a test's stand-in on one module's `paramiko` is seen by that module alone, as with the plain
import it replaces). Reading any attribute of it (paramiko.SSHClient, an exception class in an
`except`) imports the real module, once, and answers from it. paramiko has no import-time side
effect the panel relies on, and nothing reads it before a connection is made.
"""
import importlib


class LazyModule:
    """A module imported at the first attribute read, and answered from from then on."""

    def __init__(self, name):
        self._name = name

    def __getattr__(self, attr):
        return getattr(importlib.import_module(self._name), attr)

