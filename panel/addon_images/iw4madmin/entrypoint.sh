#!/bin/sh
# IW4MAdmin's start in linuxgsm-panel's add-on image: the first-start steps of IW4MAdmin's own
# entrypoint.sh (its settings file must be there; the release's default settings, plugins and
# translations fill the mounted folders when they are empty), then IW4MAdmin itself. Its user switch
# (gosu, chown) is left out: the panel already runs the container as the game account.
# No `set -e`, as in IW4MAdmin's own script: a populate step that skips files already there must not
# stop the start, and cp -n's exit status for a skipped file is not settled (coreutils 9.4 warns it may change).
set -u
cd /app
if [ ! -f Configuration/IW4MAdminSettings.json ]; then
    echo "FATAL ERROR: IW4MAdminSettings.json not found in the mounted Configuration folder." >&2
    sleep 5
    exit 1
fi
if [ ! -f Configuration/LoggingConfiguration.json ]; then
    echo "Default configuration files not found, populating..."
    cp -n /app_defaults/Configuration/* Configuration/
fi
if [ ! -f Plugins/Stats.dll ]; then
    echo "Default plugins not found, populating..."
    cp -n -r /app_defaults/Plugins/* Plugins/
fi
if [ ! -f Localization/IW4MAdmin.en-US.json ]; then
    echo "Default localization files not found, populating..."
    cp -n -r /app_defaults/Localization/* Localization/
fi
echo "Starting IW4MAdmin ${IW4MADMIN_TAG:-}..."
exec dotnet Lib/IW4MAdmin.dll
