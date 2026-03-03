#!/usr/bin/env bash

#
# Simple updater for the SSH Brute-Force Detection Lab tool.
# Run this *inside* the cloned repository on your VM to pull
# the latest changes from GitHub.
#

set -e

echo "[*] SSH Brute-Force Detection Lab - Updater"

if ! command -v git >/dev/null 2>&1; then
  echo "[!] git is not installed. Install git first (e.g. sudo apt install -y git)."
  exit 1
fi

if [ ! -d ".git" ]; then
  echo "[!] This directory is not a git repository."
  echo "    Make sure you ran 'git clone <repo-url>' and are inside that folder."
  exit 1
fi

echo "[*] Pulling latest changes from origin..."
git pull --ff-only

echo "[*] Update complete. You now have the latest version of the tool."

