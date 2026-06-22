## 使用

1. 双击运行（Windows：`recauth-launch.exe`；macOS：`RECAUTH-启动.command`）。
2. 首次运行会打开浏览器到 Hub 门户：邀请码注册 / 登录 → 点「绑定本机」→ 拿到设备 token（存
   `~/.recauth/config.json`）。
3. 之后弹出文件夹选择框，选一个**工程目录**（claude 以此为工作目录）。`claude` 本体按 PATH 自动
   定位，缺失则询问后 `npm i -g @anthropic-ai/claude-code`。
4. 重新绑定 / 换账号：`recauth-launch --recauth-login`。

> macOS 把 `RECAUTH-启动.command` 与对应架构的二进制放**同一目录**，双击 `.command` 即可（自动按
> CPU 挑选、解除 Gatekeeper 隔离）。二进制未签名：Windows 点「仍要运行」，macOS 走 `.command` 或
> 右键→打开。

## 构建

纯 Go、`CGO_ENABLED=0`，可跨平台交叉编译：

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/recauth-launch.exe       .
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/recauth-launch-mac-arm64 .
GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/recauth-launch-mac-x64   .
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/recauth-launch-linux-x64 .
```

CI（`.github/workflows/release.yml`）会在每次 push 到 `main` 时构建全部平台并发布一个
GitHub Release（tag `build<run>-<sha>`）；推一个 `v*` 语义化 tag 则发布同名 release。

## 运行时覆盖

- `RECAUTH_WS_URL` — 覆盖内置的 Hub WebSocket 端点（默认 `wss://recauth.timefiles.online/tunnel`）。
- `RECAUTH_KEY` / `RECAUTH_OAUTH_TOKEN` — 覆盖内置默认。
