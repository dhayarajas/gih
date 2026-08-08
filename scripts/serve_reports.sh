#!/bin/bash
# Ghost Identity Hunter - Serve generated reports over HTTP
#
# A report is a standalone HTML file that pulls its graph embed from a sibling
# file and its map tiles over the network, so it is easiest to read served
# rather than opened from disk. This starts python's http.server over the
# reports directory as a background job, keeping its PID so a second start
# does not stack servers on the same port.
#
# Usage:
#   scripts/serve_reports.sh [start|stop|status|restart] [-d DIR] [-p PORT] [-b ADDRESS]
#
#   scripts/serve_reports.sh                    # start on 127.0.0.1:8000 over ./reports
#   scripts/serve_reports.sh start -p 8080
#   scripts/serve_reports.sh status
#   scripts/serve_reports.sh stop
#
# The server binds to localhost by default: reports name people, carry breach
# records and, unredacted, are not fit to expose on a network. Pass
# "-b 0.0.0.0" only when that is what you intend.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ACTION="start"
case "${1:-}" in
    start|stop|status|restart) ACTION="$1"; shift ;;
esac

REPORT_DIR="${GIH_REPORT_DIR:-$PROJECT_DIR/reports}"
PORT="${GIH_REPORT_PORT:-8000}"
BIND="${GIH_REPORT_BIND:-127.0.0.1}"

while getopts ":d:p:b:h" opt; do
    case "$opt" in
        d) REPORT_DIR="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        b) BIND="$OPTARG" ;;
        h) sed -n '2,21p' "$0"; exit 0 ;;
        \?) echo "Unknown option -$OPTARG" >&2; exit 2 ;;
    esac
done

RUN_DIR="$PROJECT_DIR/logs"
PID_FILE="$RUN_DIR/report_server_$PORT.pid"
LOG_FILE="$RUN_DIR/report_server_$PORT.log"

PYTHON="python3"
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON="python"

server_pid() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    # A stale PID file outlives a killed server, and the number may since have
    # been reused, so check the process is still this server.
    [ -n "$pid" ] && ps -p "$pid" -o args= 2>/dev/null | grep -q "http.server" || return 1
    echo "$pid"
}

do_status() {
    local pid
    if pid="$(server_pid)"; then
        echo "Serving on http://$BIND:$PORT/ (pid $pid)"
        echo "  directory: $REPORT_DIR"
        echo "  log:       $LOG_FILE"
        return 0
    fi
    echo "Not running on port $PORT"
    return 1
}

do_stop() {
    local pid
    if pid="$(server_pid)"; then
        kill "$pid"
        for _ in $(seq 20); do
            ps -p "$pid" >/dev/null 2>&1 || break
            sleep 0.1
        done
        ps -p "$pid" >/dev/null 2>&1 && kill -9 "$pid" 2>/dev/null || true
        echo "Stopped report server (pid $pid)"
    else
        echo "No report server running on port $PORT"
    fi
    rm -f "$PID_FILE"
}

do_start() {
    if pid="$(server_pid)"; then
        echo "Already serving on http://$BIND:$PORT/ (pid $pid) — nothing to do"
        return 0
    fi

    if [ ! -d "$REPORT_DIR" ]; then
        echo "Report directory not found: $REPORT_DIR" >&2
        echo "Generate a report first, or pass -d with the right directory." >&2
        exit 1
    fi

    mkdir -p "$RUN_DIR"
    # setsid detaches the server from this shell, so it survives the terminal
    # that started it; without it the job dies with the session.
    if command -v setsid >/dev/null 2>&1; then
        setsid "$PYTHON" -m http.server "$PORT" --bind "$BIND" \
            --directory "$REPORT_DIR" >"$LOG_FILE" 2>&1 &
    else
        nohup "$PYTHON" -m http.server "$PORT" --bind "$BIND" \
            --directory "$REPORT_DIR" >"$LOG_FILE" 2>&1 &
    fi
    local pid=$!
    echo "$pid" >"$PID_FILE"

    sleep 0.7
    if ! ps -p "$pid" >/dev/null 2>&1; then
        rm -f "$PID_FILE"
        echo "Server failed to start; last lines of $LOG_FILE:" >&2
        tail -n 5 "$LOG_FILE" >&2 || true
        exit 1
    fi

    echo "Serving $REPORT_DIR at http://$BIND:$PORT/ (pid $pid)"
    local latest
    latest="$(ls -t "$REPORT_DIR"/*.html 2>/dev/null | head -n 1 || true)"
    [ -n "$latest" ] && echo "Latest report: http://$BIND:$PORT/$(basename "$latest")"
    echo "Log: $LOG_FILE"
    echo "Stop with: scripts/serve_reports.sh stop -p $PORT"
}

case "$ACTION" in
    start)   do_start ;;
    stop)    do_stop ;;
    status)  do_status ;;
    restart) do_stop; do_start ;;
esac
