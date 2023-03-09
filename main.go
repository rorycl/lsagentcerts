/*
lsagentcerts

Check the certificates loaded into the specified ssh agent for expiry in
the next <expiration> period (specified as a golang time.Duration).

Using a filter string one can restrict certificates containing that
string. Note that this is a simple lowercase string match.

In verbose mode all

In terse mode, return 1 if any certificate (after filtering) is expiring.

example output:

lsagentcerts -f acme -e 90m

key ssh-ed25519-cert-v01@openssh.com
    comment : acmeinc_briony_from:2023-03-08T20:46_to:2023-03-08T22:16UTC
    validity: 2023-03-08 20:10:23 GMT to 2023-03-08 22:10:23 GMT
    expires : 1h27m28s
    marked  : true
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

var (
	socket     = flag.String("s", os.Getenv("SSH_AUTH_SOCK"), "agent socket")
	filter     = flag.String("f", "", "filter by string")
	expiration = flag.Duration("e", time.Duration(60*time.Minute), "expiration window")
	verbose    = flag.Bool("v", false, "list all certificates")
	terse      = flag.Bool("t", false, "terse: exit 1 if any certs expiring")
)

var usage = `
lsagentcerts lists certificates in one's local ssh agent that are due to
expire in <expiration> periodl Certificates may be filtered. To show all
certificates use the verbose flag, or use the terse flag to exit 1 if
any certificates are due to expire.
`

func main() {

	// override flag.Usage
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), usage)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *verbose && *terse {
		fmt.Println("terse and verbose mode cannot both be set to true")
		os.Exit(1)
	}

	certs, err := agentCerts(*socket, *filter, *expiration, *verbose)
	if err != nil {
		fmt.Printf("agent listing error: %v", err)
		os.Exit(1)
	}
	for _, c := range certs {

		if *terse && c.marked {
			os.Exit(1)
		}
		if c.marked || *verbose {
			fmt.Println(c)
		}
	}
}
