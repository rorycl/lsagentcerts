/*
Check the certificates loaded into the specified ssh agent for imminent expiry

example output:

0 key ssh-ed25519 : is not a certificate
1 key ssh-ed25519-cert-v01@openssh.com
    comment:  acmeinc_briony_from:2023-03-07T08:18_to:2023-03-07T11:18UTC
    validity: 2023-03-07 08:37:23 GMT to 2023-03-07 11:37:23 GMT
    expiring in 60m? true


*/
package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// pubKey is a struct for an agent Key, the associated public key and
// certificate (if applicable)
type pubKey struct {
	key         *agent.Key
	publicKey   ssh.PublicKey
	cert        *ssh.Certificate
	isCert      bool
	validBefore time.Time
	validAfter  time.Time
}

// String represents a pubKey for printing
func (p pubKey) String() string {
	var tpl string
	if !p.isCert {
		tpl = `key %s : is not a certificate`
		return fmt.Sprintf(tpl, p.key.Format)
	}
	tpl = "key %s\n    comment:  %s\n    validity: %s to %s"
	return fmt.Sprintf(
		tpl,
		p.key.Format,
		p.key.Comment,
		p.validAfter.Format("2006-01-02 15:05:06 MST"),
		p.validBefore.Format("2006-01-02 15:05:06 MST"),
	)
}

// expiring determines if a key has expired or will expire within
// duration d specified as a string
func (p *pubKey) expiring(ds string) (bool, error) {
	if !p.isCert {
		return true, errors.New("key is not a certificate")
	}
	d, err := time.ParseDuration(ds)
	if err != nil {
		return true, fmt.Errorf("duration parse error %w", err)
	}
	t := time.Now().Add(-d)
	if p.validAfter.Before(t) {
		return true, nil
	}
	return false, nil
}

// parsePubKey is from https://gist.github.com/StevenACoffman/8e2096e7583f3a67fe3d6280b2cb882c
func newPubKey(k *agent.Key) (*pubKey, error) {
	var err error
	p := new(pubKey)
	p.key = k
	p.publicKey, err = ssh.ParsePublicKey(k.Blob)
	if err != nil {
		return p, fmt.Errorf("key parse error %w", err)
	}
	var ok bool
	p.cert, ok = p.publicKey.(*ssh.Certificate)
	if !ok {
		p.isCert = false
		return p, nil
	}
	p.isCert = true
	p.validBefore = time.Unix(int64(p.cert.ValidBefore), 0)
	p.validAfter = time.Unix(int64(p.cert.ValidAfter), 0)
	return p, nil
}

func main() {

	socket := os.Getenv("SSH_AUTH_SOCK")
	socket = "/tmp/ssh-tWye8nXDWBBG/agent.1214004" // for a particular sock
	conn, _ := net.Dial("unix", socket)
	a := agent.NewClient(conn)
	l, err := a.List()
	if err != nil {
		log.Fatalf("agent listing error: %v", err)
	}
	for i, k := range l {
		c, err := newPubKey(k)
		if err != nil {
			fmt.Println("key parsing error: ", err)
		}
		fmt.Println(i, c)
		if !c.isCert {
			continue
		}
		// expiration
		ds := "60m"
		expired, err := c.expiring(ds)
		if err != nil {
			fmt.Println("expiry error: ", err)
			continue
		}
		fmt.Printf("    expiring in %s? %t\n", ds, expired)
	}
}
