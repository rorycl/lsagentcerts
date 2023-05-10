/*
agent lister
*/
package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// agentCerts returns the certificates in the agent connected at socket,
func agentCerts(socket string) ([]*agent.Key, error) {

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return []*agent.Key{}, fmt.Errorf("socket err: %v", err)
	}

	a := agent.NewClient(conn)
	l, err := a.List()
	if err != nil {
		return l, fmt.Errorf("agent listing error: %v", err)
	}
	return l, nil

}

// keyFilter filters a key by string, an expiration duration window
// filtering the name or comment by the filter and either expired or
// expiring within a duration of expDur
func keyFilter(pk *agent.Key, filter string, expDur time.Duration) (*pubKey, error) {

	c, err := newPubKey(pk)
	if err != nil {
		return c, fmt.Errorf("key parsing error: %w", err)
	}

	// skip non-certificate keys
	if !c.isCert {
		c.isCert = false
	}

	// a naive filter
	c.filterMatch = true
	if filter != "" && c.isCert {
		c.filterMatch = false
		f := strings.ToLower(filter)
		if strings.Contains(strings.ToLower(c.key.Comment+c.key.Format), f) {
			c.filterMatch = true
		}
	}

	// expiration
	c.expiring(expDur)

	// mark filtered and expiring certificates
	c.mark()

	return c, nil
}
