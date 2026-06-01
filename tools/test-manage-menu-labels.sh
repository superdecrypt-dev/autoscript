#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
cd "${ROOT_DIR}"

legacy_patterns=(
  'ui_menu_screen_begin "10\) Tools'
  'ui_menu_screen_begin "8\) Traffic'
  'ui_menu_screen_begin "7\) Maintenance'
  'ui_menu_screen_begin "6\) Security'
  'ui_menu_screen_begin "5\) Speedtest'
  'ui_menu_screen_begin "4\) Domain Control'
  'ui_menu_screen_begin "2\) Xray QAC'
  'echo "8\) Traffic >'
  'echo "5\) Speedtest >'
  'echo "4\) Domain Control >'
  'echo "7\) Maintenance >'
  'local base="3\) Xray Network"'
  'local base="10\) Tools > WARP Tier"'
  'base="3\) Xray Network > WARP Controls > WARP Tier"'
)

for pattern in "${legacy_patterns[@]}"; do
  if rg -n "${pattern}" opt/manage >/dev/null; then
    echo "[test-manage-menu-labels] legacy numbering still present: ${pattern}" >&2
    exit 1
  fi
done

required_patterns=(
  'ui_menu_screen_begin "13\) Tools"'
  'ui_menu_screen_begin "12\) Traffic"'
  'ui_menu_screen_begin "11\) Maintenance"'
  'ui_menu_screen_begin "10\) Security"'
  'ui_menu_screen_begin "9\) Speedtest"'
  'ui_menu_screen_begin "8\) Domain Control'
  'ui_menu_screen_begin "3\) Xray QAC"'
  'echo "12\) Traffic >'
  'echo "9\) Speedtest >'
  'echo "8\) Domain Control >'
  'echo "11\) Maintenance >'
  'local base="5\) Xray Network"'
  'local base="13\) Tools > WARP Tier"'
  'base="5\) Xray Network > WARP Controls > WARP Tier"'
  '"3\|License Guard"'
  'run_action "License Guard" autoscript_license_status_menu'
)

for pattern in "${required_patterns[@]}"; do
  if ! rg -n "${pattern}" opt/manage >/dev/null; then
    echo "[test-manage-menu-labels] expected numbering missing: ${pattern}" >&2
    exit 1
  fi
done

echo "[test-manage-menu-labels] manage menu numbering looks consistent"
