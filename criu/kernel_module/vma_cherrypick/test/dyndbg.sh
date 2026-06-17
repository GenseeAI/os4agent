#!/bin/bash

MODULE_NAME="vma_cherrypick"
CTRL_FILE="/sys/kernel/debug/dynamic_debug/control"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

if [ ! -f "$CTRL_FILE" ]; then
  echo "Error: Dynamic debug control file not found."
  echo "Ensure debugfs is mounted: mount -t debugfs none /sys/kernel/debug"
  exit 1
fi

usage() {
  echo "Usage: $0 {on|off}"
  echo "  on              Enable all debug logs for $MODULE_NAME"
  echo "  off             Disable all debug logs for $MODULE_NAME"
  exit 1
}

ACTION=$1

case "$ACTION" in
  on)
    echo "Enabling logs for $MODULE_NAME..."
    echo "module $MODULE_NAME +p" > $CTRL_FILE
    ;;
  off)
    echo "Disabling all logs for $MODULE_NAME..."
    echo "module $MODULE_NAME -p" > $CTRL_FILE
    ;;
  *)
    usage
    ;;
esac

echo "--- Current Active Debug Points for $MODULE_NAME ---"
grep "$MODULE_NAME" $CTRL_FILE | grep "=p" || echo "None active."
