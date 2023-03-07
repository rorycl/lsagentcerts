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
	"fmt"
	"log"
	"time"
)

func main() {

	socket := "/tmp/ssh-1ajNkxZyueg7/agent.1300162"
	filter := ""
	expiration, err := time.ParseDuration("62m")
	if err != nil {
		log.Fatal(err)
	}
	verbose := true
	certs, err := agentCerts(socket, filter, expiration, verbose)
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range certs {
		fmt.Println(c)
	}
}
