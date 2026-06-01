#!/usr/bin/env bash
# shellcheck shell=bash

manage_router_dispatch() {
  local action="${1:-}"
  shift || true
  case "${action}" in
    "")
      return 0
      ;;
    user|users|xray-users)
      run_action "Xray Users" user_menu "$@"
      ;;
    ssh|ssh-users)
      run_action "SSH Users" ssh_menu "$@"
      ;;
    quota|qac|xray-qac)
      run_action "Xray QAC" quota_menu "$@"
      ;;
    ssh-qac)
      run_action "SSH QAC" ssh_quota_menu "$@"
      ;;
    network|xray-network)
      run_action "Xray Network" network_menu "$@"
      ;;
    ssh-network|sshnet)
      run_action "SSH Network" ssh_network_menu "$@"
      ;;
    adblock|adblocker)
      run_action "Adblocker" adblock_menu "$@"
      ;;
    domain|domain-control)
      run_action "Domain Control" domain_control_menu "$@"
      ;;
    speedtest|speed)
      run_action "Speedtest" speedtest_menu "$@"
      ;;
    security)
      run_action "Security" fail2ban_menu "$@"
      ;;
    maintenance)
      run_action "Maintenance" maintenance_menu "$@"
      ;;
    traffic|analytics)
      run_action "Traffic" traffic_analytics_menu "$@"
      ;;
    tools)
      tools_menu "$@"
      ;;
    backup|restore|backup-restore)
      run_action "Backup/Restore" backup_restore_menu "$@"
      ;;
    telegram-bot)
      run_action "Telegram Bot" install_telegram_bot_menu "$@"
      ;;
    license-guard)
      run_action "License Guard" autoscript_license_status_menu "$@"
      ;;
    uninstall)
      autoscript_uninstall_menu "$@"
      ;;
    *)
      warn "Action manage tidak dikenal: ${action}"
      return 1
      ;;
  esac
}
