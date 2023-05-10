# lsagentcerts

Version 0.0.3 : 10 May 2023

A simple tool to list expiring ssh certificates which may be suitable
for running as a cron job or ssh `Match ... exec` block as part of an
automated approach to refreshing ssh certificates.

Note that it may be advisable to remove an expiring certificate when
replacing it with a refreshed certificate else this program will still
report the expiring certificate until it is dropped by the agent.

## Usage

```
lsagentcerts lists certificates in the ssh agent at the provided socket
that are due to expire in the specified expiration period. Certificates
may be filtered. To show all certificates use the verbose flag, or use
the terse flag to exit 1 if any certificates are due to expire.

Usage of ./lsagentcerts:
  -e duration
    	expiration window (default 1h0m0s)
  -f string
    	only show certificates containing the lowercase filter string
  -s string
    	ssh agent socket, typically SSH_AUTH SOCK (default "/tmp/ssh-9qxvRBQYCOkX/agent.77431")
  -t	terse: exit 1 if any certs will expire within the expiration window
  -v	list all certificates and note non-certificate keys in the agent
```

Verbose mode includes non-expiring certificates and keys.

```
./lsagentcerts -v -e 1h20m

key  SHA256:32CvkGqZAkKhcrPZqALs0tdx+O571Ewxsddngs4qYBs
     type     : ssh-rsa
     comment  : /home/briony/.ssh/id_briony_key

key  SHA256:Ye3VV0z4vDvAuiZYqw4ji2Ht/JlDTMNlpTZoeZR+bDs
     type     : ssh-ed25519
     comment  : briony@test.com

cert SHA256:rz4rsiRFFz36ubpiEiqH/wD53QR99GbkVqL9P9A2zCI
     type     : ssh-ed25519-cert-v01@openssh.com
     comment  : acmeinc_briony_from:2023-05-10T13:02_to:2023-05-10T14:32UTC
     validity : 2023-05-10T14:02:04 to 2023-05-10T15:32:04
     expires  : 1h16m1s
     marked   : true

cert SHA256:RZd7xjHvjsD49b9StEfwXK6pnhSAL23jhfulRPixGro
     type     : ssh-ed25519-cert-v01@openssh.com
     comment  : acmeinc_briony_from:2023-05-10T13:15_to:2023-05-10T14:45UTC
     validity : 2023-05-10T14:15:37 to 2023-05-10T15:45:37
     expires  : 1h29m34s
     marked   : false
```

The expiry setting allows the expiration to be specified. Go
`time.ParseDuration` strings such as "s", "m" and "h" can be used,
including constructs such as `1h20m` as shown above.

Terse mode exits status 1 if there are expiring certificates

```
./lsagentcerts -e 90m -t || echo $?
1
```
## License

This project is licensed under the [MIT Licence](LICENCE).

Rory Campbell-Lange
