/*
Part of the ssh-agent launching code is taken from golang.org/x/crypto/ssh/agent-test.go; see below.
*/
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var regexpSOCKET = regexp.MustCompile(`SSH_AUTH_SOCK=([^;]+);`)
var regexpPID = regexp.MustCompile(`SSH_AGENT_PID=(\d+)`)

// setup an ssh-agent and return the socket as a string and a teardown
// func
func setup(t *testing.T) (string, func(*testing.T)) {
	t.Log("setup")

	// stolen from go's ssh/agent_test.go
	bin, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Fatal("could not find ssh-agent")
	}

	cmd := exec.Command(bin, "-s")
	cmd.Env = []string{} // Do not let the user's environment influence ssh-agent behavior.
	cmd.Stderr = new(bytes.Buffer)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", strings.Join(cmd.Args, " "), err, cmd.Stderr)
	}
	// end of steal

	socketMatches := regexpSOCKET.FindStringSubmatch(string(out))
	if len(socketMatches) < 2 {
		t.Fatal("could not find ssh socket")
	}
	socket := socketMatches[1]

	pidMatches := regexpPID.FindStringSubmatch(string(out))
	if len(pidMatches) < 2 {
		t.Fatal("could not find ssh pid")
	}
	pid, err := strconv.Atoi(pidMatches[1])
	if err != nil {
		t.Fatalf("could not get pid int from %v", pidMatches)
	}

	conn, err := net.Dial("unix", string(socket))
	if err != nil {
		t.Fatalf("net dial error: %v", err)
	}

	return socket, func(t *testing.T) {
		t.Log("teardown")
		// taken from ssh/agent_test.go
		proc, _ := os.FindProcess(pid)
		if proc != nil {
			proc.Kill()
		}
		conn.Close()
		os.RemoveAll(filepath.Dir(socket))
	}
}

func TestAgentCerts(t *testing.T) {

	socket, teardown := setup(t)
	defer teardown(t)

	conn, err := net.Dial("unix", string(socket))
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	sshAgent := agent.NewClient(conn)

	// keys for certificate
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("could not generate ed25519 keys %s", err)
	}

	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Errorf("could not convert ed25519 public key to ssh key %s", err)
	}

	fromT := time.Now().UTC()
	toT := time.Now().UTC().Add(time.Duration(20 * time.Minute))
	identifier := "acme_inc"
	permissions := ssh.Permissions{}

	cert := &ssh.Certificate{
		CertType:    ssh.UserCert,
		Key:         sshPubKey,
		KeyId:       identifier,
		ValidAfter:  uint64(fromT.Unix()),
		ValidBefore: uint64(toT.Unix()),
		Permissions: permissions,
	}

	// signing key
	_, privSignerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("could not generate ed25519 signer private key %s", err)
	}

	signer, err := ssh.NewSignerFromKey(privSignerKey)
	if err != nil {
		t.Errorf("could not generate signer %s", err)
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Errorf("cert signing error: %s", err)
	}

	// add certificate to agent
	err = sshAgent.Add(agent.AddedKey{
		PrivateKey:   priv,
		Certificate:  cert,
		LifetimeSecs: 20 * 60, // minutes to seconds
		Comment:      identifier,
	})
	if err != nil {
		t.Errorf("cert addition to agent error: %s", err)
	}

	// add a normal private key to the agent
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("could not generate ed25519 key for private key %s", err)
	}

	// add key to agent
	err = sshAgent.Add(agent.AddedKey{
		PrivateKey: privKey,
		Comment:    "key_only",
	})
	if err != nil {
		t.Errorf("private key addition to agent error: %s", err)
	}

	for name, test := range map[string]struct {
		socket  string
		filter  string
		expDur  time.Duration
		results int
		certs   int
		matches int
	}{
		"none expired": {
			socket:  socket,
			filter:  "",
			expDur:  1 * time.Minute,
			results: 2,
			certs:   1,
			matches: 0,
		},
		"one expired": {
			socket:  socket,
			filter:  "",
			expDur:  21 * time.Minute,
			results: 2,
			certs:   1,
			matches: 1,
		},
		"filter shows no cert": {
			socket:  socket,
			filter:  "xyz",
			expDur:  25 * time.Minute,
			results: 2,
			certs:   1,
			matches: 0,
		},
		"filter shows one cert": {
			socket:  socket,
			filter:  "acme",
			expDur:  25 * time.Minute,
			results: 2,
			certs:   1,
			matches: 1,
		},
	} {
		ac, err := agentCerts(test.socket)
		if err != nil {
			t.Errorf("name %s err %v", name, err)
		}

		keys := []*pubKey{}
		var r, c, m = 0, 0, 0
		r = len(ac)
		for _, key := range ac {
			kf, err := keyFilter(key, test.filter, test.expDur)
			if err != nil {
				t.Errorf("name %s err %v", name, err)
			}
			if kf.isCert {
				c += 1
			}
			if kf.marked {
				m += 1
			}
			keys = append(keys, kf)
		}

		if r != test.results {
			t.Errorf("name %s results got %d expected %d", name, r, test.results)
		}
		if c != test.certs {
			t.Errorf("name %s certificate number got %d expected %d", name, c, test.certs)
		}
		if m != test.matches {
			t.Errorf("name %s match number got %d expected %d", name, m, test.matches)
		}
	}
}
