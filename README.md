# lsagentcerts

Version 0.0.2 : 09 March 2023

A simple tool to list expiring ssh certificates which may be suitable
for running as a cron job or ssh `Match ... exec` block as part of an
automated approach to refreshing ssh certificates.

Note that it may be advisable to remove an expiring certificate when
replacing it with a refreshed certificate else this program will still
report the expiring certificate until it is dropped by the agent.

## Usage

```
./lsagentcerts -h

lsagentcerts lists certificates in the ssh agent at the provided socket
that are due to expire in the specified expiration period. Certificates
may be filtered. To show all certificates use the verbose flag, or use
the terse flag to exit 1 if any certificates are due to expire.

Usage of ./lsagentcerts:
  -e duration
    	expiration window (default 1h0m0s)
  -f string
    	filter by string
  -s string
    	agent socket (default SSH_AUTH_SOCK)
  -t	terse: exit 1 if any certs expiring
  -v	list all certificates
```

Verbose mode includes non-expiring certificates.

```
./lsagentcerts -v

SHA256:pAy8wKyhWyCHfgK4qnNk6ko9r0MSuV+ifmFxe60Uvlw
    type     : ssh-ed25519-cert-v01@openssh.com
    comment  : acmeinc_briony_from:2023-03-09T11:57_to:2023-03-09T13:27UTC
    validity : 2023-03-09T11:57:02 to 2023-03-09T13:27:02
    expires  : 1h18m50s
    marked   : false

SHA256:TjRGYu7eQOXVGIvd3mjGwYmHo47aTkmU0pG/hQD9g7M
    type     : ssh-ed25519-cert-v01@openssh.com
    comment  : acmeinc_briony_from:2023-03-09T12:08_to:2023-03-09T13:38UTC
    validity : 2023-03-09T12:08:04 to 2023-03-09T13:38:04
    expires  : 1h29m52s
    marked   : false
```

The expiry setting allows the expiration to be specified. Go
`time.ParseDuration` strings such as "s", "m" and "h" can be used,
including constructs such as `2h45m`.

```
./lsagentcerts -e 79m

SHA256:pAy8wKyhWyCHfgK4qnNk6ko9r0MSuV+ifmFxe60Uvlw
    type     : ssh-ed25519-cert-v01@openssh.com
    comment  : acmeinc_briony_from:2023-03-09T11:57_to:2023-03-09T13:27UTC
    validity : 2023-03-09T11:57:02 to 2023-03-09T13:27:02
    expires  : 1h18m40s
    marked   : true
```

Terse mode exits status 1 if there are expiring certificates

```
./lsagentcerts -e 90m -t || echo $?
1
```
## License

This project is licensed under the [MIT Licence](LICENCE).

Rory Campbell-Lange
