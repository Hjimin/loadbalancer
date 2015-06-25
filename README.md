# PacketNgin Loadbalancer

# CLI
	COMMAND BASIC FORMATS
	[command] [protocol] [service address:port] [nic number] [schedules method]
	[command] [protocol] [server address:port] [nic number] [forwarding method]

	COMMANDS
		service add -- Add Service.
			remove -- Remove Service. (Default = grace)
			list -- List of Service.
		server	add -- Add Real Server to Service.
			remove -- Remove Real Server from Service. (Default = grace)
			list -- List of Real Server.

	OPTIONS
		PROTOCOLS
			-t -- TCP
			-u -- UDP
		SCHEDULE OPTIONS
			rr	-- Round Robin(default).
			r	-- Random.
			min	-- Server that has min sessions.
		MODE OPTIONS
			nat	-- network address transration.
			dnat	-- destination network address transration.
			dr	-- direct routing.
		OTHERS
			-f -- Delete Force(not grace)
			-o -- Time out of session(micro second) default: 30000000

	EXAMPLES 1
		service add -t 192.168.10.100:80 0 -s rr -out 192.168.100.20 1
		service add -t 192.168.10.100:80 1 -s rr -out 192.168.100.21 1
		server add -t 192.168.10.201:8080 2 -m nat
		server add -t 192.168.10.201:8081 2 -m nat
		server add -t 192.168.10.201:8082 2 -m nat
		server add -t 192.168.10.201:8083 2 -m nat
		service list
		server list

	EXAMPLES 2
		server remove -t 192.168.10.201:8080 2
		server remove -t 192.168.10.201:8081 2
		server remove -t 192.168.10.201:8082 2
		server remove -t 192.168.10.201:8083 2
		service remove -t 192.168.10.100:80 0
# License
GPL2
