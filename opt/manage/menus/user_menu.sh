#!/usr/bin/env bash
# shellcheck shell=bash

manage_menu_user_render() {
  user_menu "$@"
}

manage_menu_ssh_render() {
  ssh_menu "$@"
}

manage_menu_xray_qac_render() {
  quota_menu "$@"
}

manage_menu_ssh_qac_render() {
  ssh_quota_menu "$@"
}
