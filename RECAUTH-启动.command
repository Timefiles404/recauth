#!/bin/bash
# RECAUTH 启动器（macOS）。双击本文件即在终端中运行：自动按 CPU 架构挑选二进制、
# 解除 Gatekeeper 隔离、补可执行权限，然后进入设备绑定 / 选目录 / 启动 Claude Code。
cd "$(dirname "$0")" || exit 1
if [ "$(uname -m)" = "arm64" ]; then
  BIN=./recauth-launch-mac-arm64
else
  BIN=./recauth-launch-mac-x64
fi
if [ ! -f "$BIN" ]; then
  echo "未找到 $BIN，请确保它与本启动器在同一目录。"
  read -r -p "按回车键退出…" _
  exit 1
fi
# 首次运行解除 macOS 隔离（未签名二进制），并补上可执行权限。
xattr -dr com.apple.quarantine "$BIN" 2>/dev/null
chmod +x "$BIN" 2>/dev/null
exec "$BIN" "$@"
