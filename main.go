/*
lsagentcerts

Check the certificates loaded into the specified ssh agent for expiry in
the next <expiration> period (specified as a golang time.Duration).

Using a filter string one can restrict certificates containing that
string. Note that this is a simple lowercase match for any certificates
containing the search string.

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
	socket     = flag.String("s", os.Getenv("SSH_AUTH_SOCK"), "ssh agent socket, typically SSH_AUTH SOCK")
	filter     = flag.String("f", "", "only show certificates containing the lowercase filter string")
	expiration = flag.Duration("e", time.Duration(60*time.Minute), "expiration window")
	verbose    = flag.Bool("v", false, "list all certificates and note non-certificate keys in the agent")
	terse      = flag.Bool("t", false, "terse: exit 1 if any certs will expire within the expiration window")
)

var usage = `
lsagentcerts lists certificates in the ssh agent at the provided socket
that are due to expire in the specified expiration period. Certificates
may be filtered. To show all certificates use the verbose flag, or use
the terse flag to exit 1 if any certificates are due to expire.
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

	certs, err := agentCerts(*socket)
	if err != nil {
		fmt.Printf("agent listing error %v\n", err)
		os.Exit(1)
	}

	for _, c := range certs {
		kf, err := keyFilter(c, *filter, *expiration)
		if err != nil {
			fmt.Printf("key parsing error: %v\n", err)
			os.Exit(1)
		}

		if *terse && kf.marked {
			os.Exit(1)
		}
		if kf.marked || *verbose {
			fmt.Println(kf)
		}
	}
}
