package netsock

import (
	"context"
	"testing"

	"github.com/karmine05/agentic-detector/internal/proc"
)

func TestCollect(t *testing.T) {
	snap := &proc.Snapshot{
		Procs: map[int]proc.Process{
			100: {PID: 100, Name: "ollama", Cmdline: "ollama serve"},
			200: {PID: 200, Name: "python", Cmdline: "python -m aider"},
			300: {PID: 300, Name: "sshd", Cmdline: "/usr/sbin/sshd -D"},
			400: {PID: 400, Name: "Electron", Cmdline: "/Applications/Claude.app/.../Electron Helper"},
		},
		Conns: []proc.Conn{
			{PID: 100, Status: "LISTEN", Type: 1, LocalIP: "127.0.0.1", LocalPort: 11434},
			{PID: 200, Status: "ESTABLISHED", Type: 1, LocalIP: "10.0.0.2", LocalPort: 5555, RemoteIP: "1.2.3.4", RemotePort: 443},
			{PID: 300, Status: "LISTEN", Type: 1, LocalIP: "0.0.0.0", LocalPort: 22},
			// Loopback IPC between Electron helpers — must NOT be flagged as egress.
			{PID: 400, Status: "ESTABLISHED", Type: 1, LocalIP: "127.0.0.1", LocalPort: 60001, RemoteIP: "127.0.0.1", RemotePort: 60002},
		},
	}

	socks := Collect(context.Background(), snap, nil)

	var listen, egress *Socket
	for i := range socks {
		switch socks[i].PID {
		case 100:
			listen = &socks[i]
		case 200:
			egress = &socks[i]
		case 300:
			t.Error("non-AI sshd listener should not be classified")
		case 400:
			t.Error("loopback IPC should not be classified as egress")
		}
	}

	if listen == nil || listen.Category != "inference-api-local" || listen.Service != "ollama" || listen.LocalPort != 11434 {
		t.Errorf("ollama listener misclassified: %+v", listen)
	}
	if egress == nil || egress.Category != "ai-api-egress" {
		t.Errorf("aider egress misclassified: %+v", egress)
	}
}

func TestNonLoopbackListenerFlag(t *testing.T) {
	cases := []struct {
		name, addr string
		want       string
	}{
		{"ipv4 loopback", "127.0.0.1", ""},
		{"ipv6 loopback", "::1", ""},
		{"localhost name", "localhost", ""},
		{"ipv4 wildcard", "0.0.0.0", "non_loopback_listener"},
		{"ipv6 wildcard", "::", "non_loopback_listener"},
		{"lsof wildcard", "*", "non_loopback_listener"},
		{"lan address", "192.168.1.20", "non_loopback_listener"},
		{"unknown address", "", ""},
		{"bracketed ipv6 loopback", "[::1]", ""},
		{"v4-mapped loopback", "::ffff:127.0.0.1", ""},
		{"v4-mapped wildcard", "::ffff:0.0.0.0", "non_loopback_listener"},
		{"link-local", "fe80::1", "non_loopback_listener"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := &proc.Snapshot{
				Procs: map[int]proc.Process{100: {PID: 100, Name: "ollama", Cmdline: "ollama serve"}},
				Conns: []proc.Conn{{PID: 100, Status: "LISTEN", Type: 1, LocalIP: tc.addr, LocalPort: 11434}},
			}
			socks := Collect(context.Background(), snap, nil)
			if len(socks) != 1 {
				t.Fatalf("want 1 socket, got %d", len(socks))
			}
			if socks[0].RiskFlags != tc.want {
				t.Errorf("addr %q: RiskFlags = %q, want %q", tc.addr, socks[0].RiskFlags, tc.want)
			}
		})
	}
}

func TestEgressNeverFlaggedAsListener(t *testing.T) {
	snap := &proc.Snapshot{
		Procs: map[int]proc.Process{200: {PID: 200, Name: "python", Cmdline: "python -m aider"}},
		Conns: []proc.Conn{{PID: 200, Status: "ESTABLISHED", Type: 1, LocalIP: "10.0.0.2", LocalPort: 5555, RemoteIP: "1.2.3.4", RemotePort: 443}},
	}
	socks := Collect(context.Background(), snap, nil)
	if len(socks) != 1 || socks[0].RiskFlags != "" {
		t.Errorf("egress socket must carry no listener flag: %+v", socks)
	}
}

func TestAgentRuntimeListenerNotFlagged(t *testing.T) {
	snap := &proc.Snapshot{
		Procs: map[int]proc.Process{500: {PID: 500, Name: "python", Cmdline: "python -m aider"}},
		Conns: []proc.Conn{{PID: 500, Status: "LISTEN", Type: 1, LocalIP: "0.0.0.0", LocalPort: 49152}},
	}
	for _, s := range Collect(context.Background(), snap, nil) {
		if s.Category == "agent-runtime" && s.RiskFlags != "" {
			t.Errorf("agent-runtime listener must not be flagged: %+v", s)
		}
	}
}
