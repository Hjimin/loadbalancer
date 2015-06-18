# PacketNgin Loadbalancer

# CLI
	COMMAND BASIC FORMATS
	[command] [protocol] [service address:port] [schedules method] [time out]
	[command] [protocol] [service address:port] [server address:port] [forwarding method] [ni number]

	COMMANDS
		service add -- Add Service.
			remove -- Remove Service. (Default = grace)
			list -- List of Service.
		server	add -- Add Real Server to Service.
			remove -- Remove Real Server from Service. (Default = grace)
			list -- List of Real Server from Service.

	OPTIONS
		PROTOCOLS
			-t -- TCP
			-u -- UDP
		SCHEDULES
			-rr -- Round Robin Algorithm.
		OTHERS
			-w -- How many time(micro seconds) wait to disconnect session. (if wait == 0, wait to disconnect all session)
			-f -- Delete Force(not grace)
			-o -- Time out of session(micro second) default: 30000000

	EXAMPLES 1
		service add -t 192.168.10.100:80 -s rr -o 40000000
		server add -t 192.168.10.100:80 -r 192.168.100.100:80 -m nat
		server add -t 192.168.10.100:80 -r 192.168.100.101:80 -m nat
		server add -t 192.168.10.100:80 -r 192.168.100.102:80 -m nat
		server add -t 192.168.10.100:80 -r 192.168.100.103:80 -m nat
		service list
		server list -t 192.168.10.100:80

	EXAMPLES 2
		server remove -t 192.168.10.100:80 -r 192.168.100.100:80 -m nat -f
		server remove -t 192.168.10.100:80 -r 192.168.100.101:80 -m nat -f
		server remove -t 192.168.10.100:80 -r 192.168.100.102:80 -m nat -w 100000
		server remove -t 192.168.10.100:80 -r 192.168.100.103:80 -m nat 
		service remove -t 192.168.10.100:80
# License
GPL2
