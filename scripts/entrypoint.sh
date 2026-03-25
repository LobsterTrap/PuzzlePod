#!/bin/bash
set -euo pipefail

# Create the demo project directory used by example scenarios
mkdir -p /tmp/puzzled-demo

# U39: Ensure runtime directory exists for puzzled pidfile and socket
mkdir -p /run/puzzled

# Start D-Bus system bus (required for puzzled <-> puzzlectl communication)
if [ ! -S /run/dbus/system_bus_socket ]; then
    dbus-daemon --system --fork
fi

# Start puzzled in the background
puzzled &
PUZZLED_PID=$!
# Q11: Ensure puzzled is terminated on container shutdown
trap "kill $PUZZLED_PID 2>/dev/null; wait $PUZZLED_PID 2>/dev/null" EXIT TERM INT

# Wait for puzzled to register on D-Bus
for i in $(seq 1 30); do
    if busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# T32: Fail-closed if puzzled didn't register
if ! busctl --system list 2>/dev/null | grep -q "org.lobstertrap.PuzzlePod1" 2>/dev/null; then
    echo "ERROR: puzzled failed to register on D-Bus within 15s" >&2
    exit 1
fi

# If a command was passed, run it; otherwise drop into a shell
if [ $# -gt 0 ]; then
    # T31: Use "$@" & wait instead of exec to preserve the trap handler
    "$@" &
    CHILD_PID=$!
    wait $CHILD_PID
    exit $?
else
    echo "puzzled running (PID $PUZZLED_PID)"
    echo ""
    echo "Quick start:"
    echo "  puzzlectl sim --run-all              # run all 7 scenarios"
    echo "  puzzlectl sim --interactive           # interactive REPL"
    echo "  puzzlectl sim --run safe_code_edit    # run one scenario"
    echo "  puzzlectl status                            # daemon status"
    echo ""
    exec /bin/bash
fi
