package workbench

import (
	"al.essio.dev/pkg/shellescape"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"github.com/sylvinus/agent-vm/internal/tailnetassets"
	"io"
	"strings"
	"time"
)

// Stage beside the installed executable so a running node can finish on its old
// inode. Identity and user data live elsewhere and are never part of installation.
const tailnetInstallScript = `set -eu; tmp=$(mktemp /tmp/cage-tailnet.XXXXXX); stage=; trap 'rm -f "$tmp"; if test -n "$stage"; then sudo rm -f "$stage"; fi' EXIT; cat > "$tmp"; stage=$(sudo mktemp /usr/local/bin/.cage-tailnet.XXXXXX); sudo install -m 0755 "$tmp" "$stage"; sudo mv -f "$stage" /usr/local/bin/cage-tailnet; printf 'cage-browser ALL=(cage) NOPASSWD: /usr/local/bin/cage-tailnet\n' | sudo tee /etc/sudoers.d/cage-tailnet >/dev/null; sudo chmod 0440 /etc/sudoers.d/cage-tailnet`

func (s *Server) refreshInstalledTailnet() error {
	installed, err := s.tailnetBinaryInstalled()
	if err != nil {
		return err
	}
	if !installed {
		return nil
	}
	// Environment updates only place the on-disk binary. The running process
	// keeps its old inode until runCage("up") restarts it; applying a saved
	// control URL against that old process can abort the update. After restart
	// the new binary reads its own persisted settings, and R5-1 plus the next
	// connect converge if they are missing.
	return s.placeTailnetBinary()
}

func (s *Server) tailnetBinaryInstalled() (bool, error) {
	if s.tailnetInstalledProbe != nil {
		return s.tailnetInstalledProbe()
	}
	ctx, cancel := context.WithTimeout(s.operationContext(), 15*time.Second)
	defer cancel()
	installed, err := s.guest(ctx, "if test -x /usr/local/bin/cage-tailnet; then printf installed; fi")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(installed)) == "installed", nil
}

func (s *Server) installTailnet() error {
	// First-time install has no running component and no guest-persisted
	// control URL, so place the binary and then apply the host's saved address.
	if err := s.placeTailnetBinary(); err != nil {
		return err
	}
	applyCtx, applyCancel := context.WithTimeout(s.operationContext(), 30*time.Second)
	defer applyCancel()
	if err := s.applySavedTailnetControl(applyCtx); err != nil {
		desired, readErr := s.readDesiredControlURL()
		if readErr != nil || desired == "" {
			desired = "已保存的控制服务器"
		}
		return fmt.Errorf("Tailscale 已安装，但未能切换到 %s：%v。连接时会再次尝试，也可在 Tailscale 面板重新保存控制服务器。", desired, err)
	}
	return nil
}

func (s *Server) placeTailnetBinary() error {
	if s.tailnetPlaceBinary != nil {
		return s.tailnetPlaceBinary()
	}
	if s.macosGuest != nil || s.windowsGuest != nil {
		return errTailnetNativeInstall
	}
	if !s.vmRunning() {
		return errors.New("请先启动 Cage 环境")
	}
	ctx, cancel := context.WithTimeout(s.operationContext(), 2*time.Minute)
	defer cancel()
	arch, err := s.guest(ctx, "uname -m")
	if err != nil {
		return err
	}
	name := "amd64"
	if string(bytes.TrimSpace(arch)) == "aarch64" {
		name = "arm64"
	} else if string(bytes.TrimSpace(arch)) != "x86_64" {
		return errors.New("当前客机架构尚不支持 Tailscale")
	}
	payload, err := tailnetassets.Linux(name)
	if err != nil {
		return errors.New("此构建缺少 Tailscale 客机组件，请安装完整的 Cage 构建")
	}
	defer payload.Close()
	reader, err := gzip.NewReader(payload)
	if err != nil {
		return err
	}
	defer reader.Close()
	script, err := s.linuxTemplate(tailnetInstallScript)
	if err != nil {
		return err
	}
	cmd := s.sshCommand(ctx, "-T", s.sshTarget(), "--", "/bin/bash -c "+shellescape.Quote(script))
	cmd.Stdin = reader
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	s.setMessage("正在安装 Tailscale，已有终端和浏览器保持运行…")
	if err := cmd.Run(); err != nil {
		return errors.New("Tailscale 安装未完成，请检查客机连接后重试")
	}
	return nil
}
