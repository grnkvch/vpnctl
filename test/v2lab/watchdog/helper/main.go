package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

const timerStartMonotonicPath = "/tmp/vpnctl-v2-watchdog-test/timer-start-monotonic-nsec"

func main() {
	if len(os.Args) < 2 {
		fatal("usage: watchdog-helper <render-units|elapsed|monotonic|arm-kill>")
	}
	switch os.Args[1] {
	case "render-units":
		if len(os.Args) != 4 {
			fatal("usage: watchdog-helper render-units <output-directory> <binary-path>")
		}
		if err := renderUnits(os.Args[2], os.Args[3]); err != nil {
			fatal(err.Error())
		}
	case "elapsed":
		if len(os.Args) != 4 {
			fatal("usage: watchdog-helper elapsed <start-rfc3339> <end-rfc3339>")
		}
		start, err := time.Parse(time.RFC3339Nano, os.Args[2])
		if err != nil {
			fatal("parse start timestamp: " + err.Error())
		}
		end, err := time.Parse(time.RFC3339Nano, os.Args[3])
		if err != nil {
			fatal("parse end timestamp: " + err.Error())
		}
		if !end.After(start) {
			fatal("end timestamp must follow start timestamp")
		}
		fmt.Printf("%.9f\n", end.Sub(start).Seconds())
	case "monotonic":
		if len(os.Args) != 2 {
			fatal("usage: watchdog-helper monotonic")
		}
		nanoseconds, err := monotonicNanoseconds()
		if err != nil {
			fatal(err.Error())
		}
		fmt.Println(nanoseconds)
	case "arm-kill":
		if len(os.Args) != 2 {
			fatal("usage: watchdog-helper arm-kill")
		}
		if err := armAndKill(); err != nil {
			fatal(err.Error())
		}
	default:
		fatal("unknown watchdog helper command")
	}
}

func renderUnits(outputDirectory, binaryPath string) error {
	units, err := linuxplatform.RenderWatchdogUnits(binaryPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		return err
	}
	for _, unit := range units {
		if err := os.WriteFile(filepath.Join(outputDirectory, unit.Name), unit.Content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func armAndKill() error {
	delegate := operations.NewSystemdWatchdogSupervisor(linuxplatform.OSProbeRunner{})
	watchdog, err := operations.NewWatchdog(
		store.DefaultPaths(),
		linuxplatform.NewOSNetworkManager(),
		&recordingSupervisor{delegate: delegate},
	)
	if err != nil {
		return err
	}
	transaction, err := watchdog.Arm(context.Background(), operations.WatchdogArmInput{
		AllowedSSHPort: 22,
		NetworkScope: linuxplatform.OwnedNetworkScope{Sysctls: []string{
			"net.ipv4.conf.all.accept_redirects",
			"net.ipv4.conf.all.rp_filter",
			"net.ipv4.conf.all.src_valid_mark",
			"net.ipv4.ip_forward",
		}},
	})
	if err != nil {
		return err
	}
	if err := applyCandidate(); err != nil {
		return err
	}
	if err := watchdog.MarkActivated(transaction.ID); err != nil {
		return err
	}
	if err := unix.Kill(os.Getpid(), unix.SIGKILL); err != nil {
		return fmt.Errorf("kill initiating CLI: %w", err)
	}
	return fmt.Errorf("initiating CLI unexpectedly survived SIGKILL")
}

type recordingSupervisor struct {
	delegate operations.WatchdogSupervisor
}

func (supervisor *recordingSupervisor) StartTimer(ctx context.Context, transactionID string) error {
	nanoseconds, err := monotonicNanoseconds()
	if err != nil {
		return err
	}
	if err := os.WriteFile(timerStartMonotonicPath, []byte(fmt.Sprintf("%d\n", nanoseconds)), 0o600); err != nil {
		return fmt.Errorf("record timer monotonic start boundary: %w", err)
	}
	return supervisor.delegate.StartTimer(ctx, transactionID)
}

func (supervisor *recordingSupervisor) TriggerRollback(ctx context.Context, transactionID string) error {
	return supervisor.delegate.TriggerRollback(ctx, transactionID)
}

func (supervisor *recordingSupervisor) StopTimer(ctx context.Context, transactionID string) error {
	return supervisor.delegate.StopTimer(ctx, transactionID)
}

func monotonicNanoseconds() (int64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0, fmt.Errorf("read monotonic clock: %w", err)
	}
	return now.Sec*int64(time.Second) + now.Nsec, nil
}

func applyCandidate() error {
	nftables := []byte(`delete table inet vpnctl
table inet vpnctl {
  chain candidate {
    type filter hook input priority filter; policy drop;
  }
}
`)
	if err := runWithInput(nftables, "nft", "--file", "-"); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"-4", "route", "flush", "table", "20001"},
		{"-4", "route", "flush", "table", "20002"},
		{"-4", "route", "add", "blackhole", "default", "metric", "99", "table", "20001"},
		{"-4", "route", "add", "unreachable", "default", "metric", "88", "table", "20002"},
		{"-4", "rule", "del", "priority", "10020", "fwmark", "0x02000000/0xff000000", "table", "20001"},
		{"-4", "rule", "add", "priority", "10000", "fwmark", "0x03000000/0xff000000", "table", "20002"},
		{"-4", "rule", "add", "priority", "10010", "fwmark", "0x04000000/0xff000000", "table", "20002"},
		{"-4", "rule", "add", "priority", "10020", "fwmark", "0x02000000/0xff000000", "table", "20001"},
	} {
		if err := run("ip", args...); err != nil {
			return err
		}
	}
	for _, assignment := range []string{
		"net.ipv4.ip_forward=1",
		"net.ipv4.conf.all.src_valid_mark=1",
		"net.ipv4.conf.all.rp_filter=1",
	} {
		if err := run("sysctl", "-q", "-w", assignment); err != nil {
			return err
		}
	}
	return nil
}

func run(name string, args ...string) error {
	return runWithInput(nil, name, args...)
}

func runWithInput(input []byte, name string, args ...string) error {
	command := exec.Command(name, args...)
	if input != nil {
		reader, writer, err := os.Pipe()
		if err != nil {
			return err
		}
		if _, err := writer.Write(input); err != nil {
			_ = reader.Close()
			_ = writer.Close()
			return err
		}
		if err := writer.Close(); err != nil {
			_ = reader.Close()
			return err
		}
		command.Stdin = reader
		defer reader.Close()
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, output)
	}
	return nil
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
