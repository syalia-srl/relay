package relay_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const operatorKey = "operator-key-0123456789"

type relayProcess struct {
	address string
	port    int
	url     string
	http    string
	command *exec.Cmd
	log     *os.File
	exited  chan struct{}
	stopped bool
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(working)
}

func relayBinary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("RELAY_BIN"); path != "" {
		return path
	}
	return filepath.Join(repositoryRoot(t), "server", "relay")
}

func privateAddress(t *testing.T) string {
	t.Helper()
	if address := os.Getenv("RELAY_TEST_ADDR"); address != "" {
		return address
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range interfaces {
		addresses, err := item.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			ipv4 := ip.To4()
			if ipv4 == nil || ip.To4() == nil {
				continue
			}
			if ipv4[0] == 10 ||
				(ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) ||
				(ipv4[0] == 192 && ipv4[1] == 168) {
				return ipv4.String()
			}
		}
	}
	t.Fatal("no private IPv4 address to serve the relay on; set RELAY_TEST_ADDR")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func keysDocument() map[string]any {
	digest := sha256.Sum256([]byte(operatorKey))
	return map[string]any{
		"relay_id": "relay.test",
		"issuers":  map[string]string{},
		"keys": []map[string]any{{
			"id":                 "operator",
			"sha256":             hex.EncodeToString(digest[:]),
			"channels":           1000,
			"creates_per_minute": 1000,
			"bytes_per_day":      100_000_000,
		}},
	}
}

func startRelay(t *testing.T, root string) *relayProcess {
	t.Helper()
	binary := relayBinary(t)
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("build the Go relay or set RELAY_BIN (looked for %s)", binary)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	address := privateAddress(t)
	port := freePort(t)
	keysPath := filepath.Join(root, "keys.json")
	document, err := json.Marshal(keysDocument())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "relay.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary)
	command.Env = append(os.Environ(),
		"RELAY_ADDR="+fmt.Sprintf("0.0.0.0:%d", port),
		"RELAY_STATE_PATH="+filepath.Join(root, "channels.json"),
		"RELAY_KEYS_PATH="+keysPath,
		"RELAY_V0=off",
	)
	command.Stdout = log
	command.Stderr = log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	relay := &relayProcess{
		address: address,
		port:    port,
		url:     fmt.Sprintf("ws://%s:%d", address, port),
		http:    fmt.Sprintf("http://127.0.0.1:%d", port),
		command: command,
		log:     log,
		exited:  make(chan struct{}),
	}
	go func() {
		_ = command.Wait()
		close(relay.exited)
	}()
	t.Cleanup(func() { relay.stop(t) })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-relay.exited:
			t.Fatalf("the relay exited at once:\n%s", relay.logs(logPath))
		default:
		}
		connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			connection.Close()
			return relay
		}
		time.Sleep(20 * time.Millisecond)
	}
	relay.stop(t)
	t.Fatalf("the relay never listened:\n%s", relay.logs(logPath))
	return nil
}

func (r *relayProcess) logs(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

func (r *relayProcess) stop(t *testing.T) {
	t.Helper()
	if r == nil || r.stopped {
		return
	}
	r.stopped = true
	if r.command.Process != nil {
		_ = r.command.Process.Signal(os.Interrupt)
		select {
		case <-r.exited:
		case <-time.After(10 * time.Second):
			_ = r.command.Process.Kill()
			<-r.exited
		}
	}
	if r.log != nil {
		r.log.Close()
	}
}
