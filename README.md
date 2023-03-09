# lsagentcerts

version 0.0.1 : 09 March 2023

A simple tool to list expiring ssh certificates.

```
./lsagentcerts -h

lsagentcerts lists certificates in one's local ssh agent that are due to
expire in <expiration> periodl Certificates may be filtered. To show all
certificates use the verbose flag, or use the terse flag to exit 1 if
any certificates are due to expire.

Usage of ./lsagentcerts:
  -e duration
    	expiration window (default 1h0m0s)
  -f string
    	filter by string
  -s string
    	agent socket (default "/tmp/ssh-gG4GQY9URBRr/agent.1406722")
  -t	terse: exit 1 if any certs expiring
  -v	list all certificates
```

Verbose mode includes non-expiring certificates.

```
./lsagentcerts -v

key ssh-ed25519-cert-v01@openssh.com
    comment : acmeinc_briony_from:2023-03-09T00:31_to:2023-03-09T02:01UTC
    validity: 2023-03-09 00:21:23 GMT to 2023-03-09 02:21:23 GMT
    expires : 1h19m23s
    marked  : false
```

Terse mode exits status 1 if there are expiring certificates
```
./lsagentcerts -e 90m -t || echo $?
1
```
## License

This project is licensed under the [MIT Licence](LICENCE).

Rory Campbell-Lange
