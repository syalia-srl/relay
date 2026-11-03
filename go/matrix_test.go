package relay_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	relay "github.com/syalia-srl/relay/go"
)

type partnerProcess struct {
	command *exec.Cmd
	input   interface {
		Write([]byte) (int, error)
		Close() error
	}
	events  chan map[string]any
	exited  chan struct{}
	mu      sync.Mutex
	errors  strings.Builder
	stopped bool
}

func startPartner(t *testing.T, language, mode string, arguments ...string) *partnerProcess {
	t.Helper()
	root := repositoryRoot(t)
	var command *exec.Cmd
	switch language {
	case "py":
		arguments = append([]string{
			"run", "--project", filepath.Join(root, "py"), "--group", "test",
			"python", filepath.Join(root, "js", "test-support", "python_partner.py"), mode,
		}, arguments...)
		command = exec.Command("uv", arguments...)
	case "js":
		arguments = append([]string{
			filepath.Join(root, "js", "test-support", "partner.js"), mode,
		}, arguments...)
		command = exec.Command("node", arguments...)
	default:
		t.Fatalf("unknown partner language %q", language)
	}
	command.Dir = root
	standardInput, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	standardOutput, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	standardError, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	partner := &partnerProcess{
		command: command,
		input:   standardInput,
		events:  make(chan map[string]any, 64),
		exited:  make(chan struct{}),
	}
	go func() {
		scanner := bufio.NewScanner(standardOutput)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		for scanner.Scan() {
			var event map[string]any
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				partner.events <- event
			}
		}
		close(partner.events)
	}()
	go func() {
		scanner := bufio.NewScanner(standardError)
		for scanner.Scan() {
			partner.mu.Lock()
			partner.errors.WriteString(scanner.Text())
			partner.errors.WriteString("\n")
			partner.mu.Unlock()
		}
	}()
	go func() {
		_ = command.Wait()
		close(partner.exited)
	}()
	t.Cleanup(func() { partner.stop(t) })
	return partner
}

func (p *partnerProcess) send(t *testing.T, command map[string]any) {
	t.Helper()
	data, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if _, err := p.input.Write(data); err != nil {
		t.Fatal(err)
	}
}

func (p *partnerProcess) next(t *testing.T, name string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case event, open := <-p.events:
			if !open {
				t.Fatalf("the %s partner exited before it said %s\n%s", p.command.Args[0], name, p.output())
			}
			if event["event"] == "error" {
				t.Fatalf("the %s partner failed: %v\n%s", p.command.Args[0], event["message"], p.output())
			}
			if event["event"] == name {
				return event
			}
		case <-deadline:
			t.Fatalf("the %s partner never said %s\n%s", p.command.Args[0], name, p.output())
		}
	}
}

func (p *partnerProcess) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.errors.String()
}

func (p *partnerProcess) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	data, _ := json.Marshal(map[string]any{"stop": true})
	_, _ = p.input.Write(append(data, '\n'))
	_ = p.input.Close()
	select {
	case <-p.exited:
	case <-time.After(30 * time.Second):
		if p.command.Process != nil {
			_ = p.command.Process.Kill()
		}
		<-p.exited
	}
}

func TestCrossLanguageMatrix(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is not installed")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	directory := t.TempDir()
	process := startRelay(t, filepath.Join(directory, "relay"))
	for _, hostLanguage := range []string{"py", "js", "go"} {
		for _, guestLanguage := range []string{"py", "js", "go"} {
			hostLanguage, guestLanguage := hostLanguage, guestLanguage
			t.Run(hostLanguage+"-host-"+guestLanguage+"-guest", func(t *testing.T) {
				directory := t.TempDir()
				ctx, cancel := timeoutContext(t, 60*time.Second)
				defer cancel()
				var host *relay.Host
				var pairing *relay.Pairing
				var hostPartner *partnerProcess
				var payload string
				if hostLanguage == "go" {
					var err error
					host, err = relay.OpenHost(ctx, relay.FileStore(filepath.Join(directory, "host")), []relay.Relay{
						{URL: process.url, Key: operatorKey},
					})
					if err != nil {
						t.Fatal(err)
					}
					defer host.Close()
					pairing, err = host.Pair(ctx, "go")
					if err != nil {
						t.Fatal(err)
					}
					payload = pairing.Payload()
				} else {
					hostPartner = startPartner(t, hostLanguage, "host",
						"--state", filepath.Join(directory, "host"),
						"--relay", process.url,
						"--key", operatorKey,
					)
					event := hostPartner.next(t, "pairing", 30*time.Second)
					payload, _ = event["payload"].(string)
				}

				var guest *relay.Guest
				var link *relay.PairedHost
				var guestPartner *partnerProcess
				var code string
				if guestLanguage == "go" {
					var err error
					guest, err = relay.OpenGuest(ctx, relay.FileStore(filepath.Join(directory, "guest")), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer guest.Close()
					link, err = guest.Pair(ctx, payload)
					if err != nil {
						t.Fatal(err)
					}
					code = link.Code()
				} else {
					guestPartner = startPartner(t, guestLanguage, "guest",
						"--state", filepath.Join(directory, "guest"),
						"--payload", payload,
					)
					event := guestPartner.next(t, "code", 30*time.Second)
					code, _ = event["code"].(string)
				}
				if len(code) != 6 {
					t.Fatalf("the code is %q", code)
				}

				var device *relay.Device
				if hostLanguage == "go" {
					var err error
					device, err = pairing.Confirm(ctx, code)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					hostPartner.send(t, map[string]any{"code": code})
					hostPartner.next(t, "bound", 30*time.Second)
				}
				if guestLanguage == "go" {
					if err := link.Bound(ctx); err != nil {
						t.Fatal(err)
					}
				} else {
					guestPartner.next(t, "bound", 30*time.Second)
				}

				fromHost := []byte("from host")
				if hostLanguage == "go" {
					if err := device.Send(ctx, fromHost); err != nil {
						t.Fatal(err)
					}
				} else {
					hostPartner.send(t, map[string]any{"send": base64.StdEncoding.EncodeToString(fromHost)})
					hostPartner.next(t, "sent", 30*time.Second)
				}
				var receivedByGuest []byte
				if guestLanguage == "go" {
					message, err := link.Recv(ctx)
					if err != nil {
						t.Fatal(err)
					}
					receivedByGuest = message
				} else {
					event := guestPartner.next(t, "message", 30*time.Second)
					encoded, _ := event["data"].(string)
					receivedByGuest, _ = base64.StdEncoding.DecodeString(encoded)
				}
				if string(receivedByGuest) != string(fromHost) {
					t.Fatalf("the guest received %q, want %q", receivedByGuest, fromHost)
				}

				fromGuest := []byte("from guest")
				if guestLanguage == "go" {
					if err := link.Send(ctx, fromGuest); err != nil {
						t.Fatal(err)
					}
				} else {
					guestPartner.send(t, map[string]any{"send": base64.StdEncoding.EncodeToString(fromGuest)})
					guestPartner.next(t, "sent", 30*time.Second)
				}
				var receivedByHost []byte
				if hostLanguage == "go" {
					_, message, err := host.Recv(ctx)
					if err != nil {
						t.Fatal(err)
					}
					receivedByHost = message
				} else {
					event := hostPartner.next(t, "message", 30*time.Second)
					encoded, _ := event["data"].(string)
					receivedByHost, _ = base64.StdEncoding.DecodeString(encoded)
				}
				if string(receivedByHost) != string(fromGuest) {
					t.Fatalf("the host received %q, want %q", receivedByHost, fromGuest)
				}

				if guestLanguage == "go" {
					if err := link.Unpair(ctx); err != nil && !errors.Is(err, relay.ErrClosed) {
						t.Fatal(err)
					}
				} else {
					guestPartner.stop(t)
				}
				if hostLanguage != "go" {
					hostPartner.stop(t)
				}
			})
		}
	}
}
