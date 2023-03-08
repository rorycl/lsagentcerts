package main

/*
	"crypto/ed25519"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh"
*/

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
		t.Fatalf("net.Dial: %v", err)
	}

	return socket, func(t *testing.T) {
		t.Log("teardown")
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
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("could not generate ed25519 keys %s", err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
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

	err = sshAgent.Add(agent.AddedKey{
		PrivateKey:   privKey,
		Certificate:  cert,
		LifetimeSecs: 20 * 60, // minutes to seconds
		Comment:      identifier,
	})
	if err != nil {
		t.Errorf("cert signing error: %s", err)
	}

	acerts, err := agentCerts(socket, "", time.Duration(1*time.Minute), false)
	if len(acerts) != 0 {
		t.Errorf("expected 0 certs, got %d", len(acerts))
	}

	acerts, err = agentCerts(socket, "", time.Duration(21*time.Minute), false)
	if len(acerts) != 1 {
		t.Errorf("expected 1 certs, got %d", len(acerts))
	}

	acerts, err = agentCerts(socket, "", time.Duration(19*time.Minute), true)
	if len(acerts) != 1 {
		t.Errorf("expected 1 certs, got %d", len(acerts))
	}

	acerts, err = agentCerts(socket, "xyz", time.Duration(25*time.Minute), false)
	if len(acerts) != 0 {
		t.Errorf("expected 0 certs, got %d", len(acerts))
	}

	acerts, err = agentCerts(socket, "acme", time.Duration(25*time.Minute), false)
	if len(acerts) != 1 {
		t.Errorf("expected 1 certs, got %d", len(acerts))
	}

}
