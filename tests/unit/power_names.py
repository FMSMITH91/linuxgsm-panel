"""The power and escalation command names the reboot checks put refusing stand-ins under.

Shared by reboot41_a (part41's reboot blocks) and part124 (the installer's update path). It sits in a
module of its own, with no side effect, because reboot41_a is part41's: importing it runs part41's
fixture setup and its checks, and pushes a request context only part41 pops. A part that wanted just
this list imported all of that, which ran part41's code inside its own and left the context behind
for every part after it.
"""
POWER_NAMES = ("reboot", "shutdown", "poweroff", "halt", "systemctl", "loginctl", "telinit",
               "init", "kexec", "busctl", "dbus-send", "gdbus", "sudo", "doas", "pkexec", "run0",
               "su", "env")
