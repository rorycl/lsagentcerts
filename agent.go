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
// filtering the name or comment by the filter and either expired or
// expiring within a duration of expDur. If verbose is true all
// certificates are returned with those matching the the filter and
// expiration criteria marked as expiring
func agentCerts(socket, filter string, expDur time.Duration, verbose bool) ([]*pubKey, error) {

	pks := []*pubKey{}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return pks, fmt.Errorf("socket err: %v", err)
	}

	a := agent.NewClient(conn)
	l, err := a.List()
	if err != nil {
		return pks, fmt.Errorf("agent listing error: %v", err)
	}

	for _, k := range l {
		c, err := newPubKey(k)
		if err != nil {
			return pks, fmt.Errorf("key parsing error: %w", err)
		}

		// skip non-certificate keys
		if !c.isCert {
			continue
		}

		// a naive filter
		matched := true
		if filter != "" {
			matched = false
			f := strings.ToLower(filter)
			if strings.Contains(strings.ToLower(c.key.Comment+c.key.Format), f) {
				matched = true
			}
		}

		// expiration
		expiring := c.expiring(expDur)

		// mark filtered and expiring certificates
		if matched && expiring {
			c.mark()
			pks = append(pks, c)
		} else if matched && verbose {
			pks = append(pks, c)
		}
	}

	return pks, nil
}
