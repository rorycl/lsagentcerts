/*
key/pubKey represents a public key in an ssh agent, which might be a certificate.
*/
package main

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// outputTemplate is a string representation
var outputTemplate = `%s
    type     : %s
    comment  : %s
    validity : %s to %s
    expires  : %s
    marked   : %t
`

// pubKey is a struct for an agent Key, the associated public key and
// certificate (if applicable)
type pubKey struct {
	key         *agent.Key
	publicKey   ssh.PublicKey
	cert        *ssh.Certificate
	isCert      bool
	validBefore time.Time
	validAfter  time.Time
	expiresIn   time.Duration
	marked      bool // marked for display
}

// String represents a pubKey for printing
func (p pubKey) String() string {
	var tpl string
	if !p.isCert {
		tpl = `key %s : is not a certificate`
		return fmt.Sprintf(tpl, p.key.Format)
	}
	tpl = outputTemplate
	return fmt.Sprintf(
		tpl,
		p.fingerprint(),
		p.publicKey.Type(),
		p.key.Comment,
		p.validAfter.Format("2006-01-02T15:04:05"),
		p.validBefore.Format("2006-01-02T15:04:05"),
		p.expiresIn.Round(time.Second),
		p.marked,
	)
}

// expiring determines if a key has expired or will expire within
// duration d
func (p *pubKey) expiring(d time.Duration) bool {
	if !p.isCert {
		panic("key is not a certificate")
	}
	t := time.Now()
	p.expiresIn = p.validBefore.Sub(t)
	a := p.validBefore.Add(-d)
	if a.Before(t) {
		return true
	}
	return false
}

// mark sets a key as "marked" for display
func (p *pubKey) mark() {
	p.marked = true
}

// fingerprint returns the sha256 fingerprint of the key
func (p *pubKey) fingerprint() string {
	return ssh.FingerprintSHA256(p.cert.Key)
}

// newPubKey returns a new pubKey from an *ssh/agent.Key
// parse is from https://gist.github.com/StevenACoffman/8e2096e7583f3a67fe3d6280b2cb882c
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
