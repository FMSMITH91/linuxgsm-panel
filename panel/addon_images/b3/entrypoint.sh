#!/bin/sh
# The B3 add-on's start (Containerfile beside this). /data is the add-on's own folder on the host:
# b3.ini (written by the panel), the plugins' settings, B3's log and its home (~/.b3). A plugin's
# settings file is copied from B3's samples the first time only, so edits made later are kept.
set -eu
mkdir -p /data/conf
for f in /opt/b3/b3/conf/plugin_*; do
    [ -e "/data/conf/${f##*/}" ] || cp "$f" "/data/conf/${f##*/}"
done
# exec: Python is the container's first process and gets the stop signal itself (B3 shuts down
# cleanly on SIGTERM and exits 0).
exec python /opt/b3/b3_run.py -c /data/b3.ini
