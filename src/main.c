#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <thread.h>
#include <net/ni.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <util/list.h>
#include <util/map.h>
#include <util/event.h>
#include <util/cmd.h>
#include <util/types.h>
#include <readline.h>

#include "service.h"
#include "server.h"
#include "session.h"
#include "loadbalancer.h"

#define DEFAULT_TIMEOUT		30000000 //30sec

static bool is_continue;

static uint32_t str_to_adr(char* argv) {
	char* str = argv;
	uint32_t address = (strtol(str, &str, 0) & 0xff) << 24; str++;
	address |= (strtol(str, &str, 0) & 0xff) << 16; str++;
	address |= (strtol(str, &str, 0) & 0xff) << 8; str++;
	address |= strtol(str, NULL, 0) & 0xff;

	return address;
}

static uint16_t str_to_port(char* argv) {
	char* str = argv;
	strtol(str, &str, 0);
	str++;
	strtol(str, &str, 0);
	str++;
	strtol(str, &str, 0);
	str++;
	strtol(str, &str, 0);
	str++;
	uint16_t port = strtol(str, &str, 0) & 0xffff;

	return port;
}

static int cmd_exit(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	if(argc == 1) {
		//TODO grace
		is_continue = false;
		return 0;
	}

	if(argc == 2) {
		if(!strcmp(argv[1], "-f")) {
			is_continue = false;
		}
	} else {
		return -1;
	}

	return 0;
}

static int cmd_service(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	if(!strcmp(argv[1], "add")) {
		int i = 2;
		uint8_t protocol = 0;
		uint32_t addr = 0;
		uint16_t port = 0;
		uint8_t schedule = LB_SCHEDULE_ROUND_ROBIN;
		uint8_t ni_num = 0;
		uint64_t timeout = DEFAULT_TIMEOUT;

		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t")) {
				i++;
				protocol = IP_PROTOCOL_TCP;
				addr = str_to_adr(argv[i]);
				port = str_to_port(argv[i]);

				continue;
			} else if(!strcmp(argv[i], "-u")) {
				i++;
				protocol = IP_PROTOCOL_UDP;
				addr = str_to_adr(argv[i]);
				port = str_to_port(argv[i]);

				continue;
			} else if(!strcmp(argv[i], "-s")) {
				i++;
				if(!strcmp(argv[i], "rr"))
					schedule = LB_SCHEDULE_ROUND_ROBIN;
				else
					return i;

				continue;
			} else if(!strcmp(argv[i], "-p")) {
				i++;
				if(is_uint8(argv[i]))
					ni_num = parse_uint8(argv[i]);
				else
					return i;

				continue;
			} else if(!strcmp(argv[i], "-o")) {
				i++;
				if(is_uint64(argv[i]))
					timeout = parse_uint64(argv[i]);
				else
					return i;

				continue;
			} else
				return i;

		}
			
		service_add(protocol, addr, port, schedule, ni_num, timeout);

		return 0;
	} else if(!strcmp(argv[1], "delete")) {
		int i = 2;
		bool is_force = false;
		uint8_t protocol = 0;
		uint32_t addr = 0;
		uint16_t port = 0;
		uint64_t wait = 0;
		uint8_t ni_num = 0;

		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t")) {
				i++;
				protocol = IP_PROTOCOL_TCP;
				addr = str_to_adr(argv[i]);
				port = str_to_port(argv[i]);

				continue;
			} else if(!strcmp(argv[i], "-u")) {
				i++;
				protocol = IP_PROTOCOL_UDP;
				addr = str_to_adr(argv[i]);
				port = str_to_port(argv[i]);

				continue;
			} else if(!strcmp(argv[i], "-w")) {
				i++;
				if(is_uint64(argv[i]))
					wait = parse_uint64(argv[i]);
				else
					return i;

				continue;
			} else if(!strcmp(argv[i], "-p")) {
				i++;
				if(is_uint8(argv[i]))
					ni_num = parse_uint8(argv[i]);
				else
					return i;

				continue;
			} else
				return i;
		}

		if(!is_force)
			service_remove(protocol, addr, port, ni_num, wait); //grace
		else
			service_remove_force(protocol, addr, port, ni_num);

		return 0;
	} else if(!strcmp(argv[1], "list")) {
		printf("Loadbalancer Service List\n");
		service_dump();

		return 0;
	} else
		return -1;

	return 0;
}

static int cmd_server(int argc, char** argv, void(*callback)(char* result, int exit_status)) {
	if(!strcmp(argv[1], "add")) {
		int i = 2;
		uint8_t protocol = 0;
		uint32_t service_addr = 0;
		uint16_t service_port = 0;
		uint8_t service_ni_num = 0;
		uint32_t server_addr = 0;
		uint16_t server_port = 0;
		uint8_t mode = LB_MODE_NAT;
		uint8_t ni_num = 0;

		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t")) {
				i++;
				protocol = IP_PROTOCOL_TCP;
				service_addr = str_to_adr(argv[i]);
				service_port = str_to_port(argv[i]);
				if(!strcmp(argv[i + 1], "-p")) {
					i++;
					i++;
					if(is_uint8(argv[i]))
						service_ni_num = parse_uint8(argv[i]);
					else
						return i;
				}
				continue;
			} else if(!strcmp(argv[i], "-u")) {
				i++;
				protocol = IP_PROTOCOL_UDP;
				service_addr = str_to_adr(argv[i]);
				service_port = str_to_port(argv[i]);
				if(!strcmp(argv[i + 1], "-p")) {
					i++;
					i++;
					if(is_uint8(argv[i]))
						service_ni_num = parse_uint8(argv[i]);
					else
						return i;
				}
				continue;
			} else if(!strcmp(argv[i], "-r")) {
				i++;
				protocol = IP_PROTOCOL_TCP;
				server_addr = str_to_adr(argv[i]);
				server_port = str_to_port(argv[i]);
				if(!strcmp(argv[i + 1], "-p")) {
					i++;
					i++;
					if(is_uint8(argv[i]))
						ni_num = parse_uint8(argv[i]);
					else
						return i;
				}
				continue;
			} else if(!strcmp(argv[i], "-m")) {
				i++;
				if(!strcmp(argv[i], "nat")) {
					mode = LB_MODE_NAT;
					continue;
				} else if(!strcmp(argv[i], "dnat")) {
					mode = LB_MODE_DNAT;
					continue;
				} else if(!strcmp(argv[i], "dr")) {
					mode = LB_MODE_DR;
					continue;
				} else
					return i;
			} else
				return i;
		}

		server_add(protocol, service_addr, service_port, service_ni_num, server_addr, server_port, mode, ni_num);

		return 0;
	} else if(!strcmp(argv[1], "delete")) {
		int i = 2;
		uint8_t protocol = 0;
		uint32_t service_addr = 0;
		uint16_t service_port = 0;
		uint8_t service_ni_num = 0;
		uint32_t server_addr = 0;
		uint16_t server_port = 0;
		uint8_t ni_num = 0;
		bool is_force = false;
		uint64_t wait = 0; //wait == 0 ;wait to disconnect all session.

		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t")) {
				i++;
				protocol = IP_PROTOCOL_TCP;
				service_addr = str_to_adr(argv[i]);
				service_port = str_to_port(argv[i]);
				if(!strcmp(argv[i + 1], "-p")) {
					i++;
					i++;
					if(!is_uint8(argv[i]))
						return i;

					service_ni_num = parse_uint8(argv[i]);
				}
				continue;
			} else if(!strcmp(argv[i], "-u")) {
				i++;
				protocol = IP_PROTOCOL_UDP;
				service_addr = str_to_adr(argv[i]);
				service_port = str_to_port(argv[i]);
				if(!strcmp(argv[i + 1], "-p")) {
					i++;
					i++;
					if(!is_uint8(argv[i]))
						return i;

					service_ni_num = parse_uint8(argv[i]);
				}
				continue;
			} else if(!strcmp(argv[i], "-r")) {
				i++;
				server_addr = str_to_adr(argv[i]);
				server_port = str_to_port(argv[i]);
				if(!strcmp(argv[i + 1], "-p")) {
					i++;
					i++;
					if(!is_uint8(argv[i]))
						return i;

					ni_num = parse_uint8(argv[i]);
				}
				continue;
			} else if(!strcmp(argv[i], "-f")) {
				is_force = true;
				continue;
			} else if(!strcmp(argv[i], "-w")) {
				i++;
				if(is_uint64(argv[i]))
					wait = parse_uint64(argv[i]);
				else
					return i;

				continue;
			} else
				return i;
		}

		bool result;
		if(is_force) {
			result = server_remove_force(protocol, service_addr, service_port, service_ni_num, server_addr, server_port, ni_num);
		} else {
			result = server_remove(protocol, service_addr, service_port, service_ni_num, server_addr, server_port, ni_num, wait);
		}

		if(!result)
			printf("Delete fail\n");

		return 0;
	} else if(!strcmp(argv[1], "list")) {
		int i = 2;
		uint8_t protocol = 0;
		uint32_t service_addr = 0;
		uint16_t service_port = 0;
		uint8_t service_ni_num = 0;

		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t")) {
				i++;
				protocol = IP_PROTOCOL_TCP;
				service_addr = str_to_adr(argv[i]);
				service_port = str_to_port(argv[i]);
				continue;
			} else if(!strcmp(argv[i], "-u")) {
				i++;
				protocol = IP_PROTOCOL_UDP;
				service_addr = str_to_adr(argv[i]);
				service_port = str_to_port(argv[i]);
				continue;
			} else if(!strcmp(argv[i], "-p")) {
				i++;
				if(!is_uint8(argv[i]))
					return i;

				service_ni_num = parse_uint8(argv[i]);
				continue;
			} else
				return i;
		}

		printf("Server List\n");
		server_dump(protocol, service_addr, service_port, service_ni_num);
		return 0;
	} else
		return -1;

	return 0;
}

Command commands[] = {
	{
		.name = "exit",
		.desc = "Exit LoadBalancer",
		.func = cmd_exit
	},
	{
		.name = "service",
		.desc = "Set Service",
		.args = "-set [ni name] ip [new ip] gw [new gateway] mask [new netmask] port [new port]",
		.func = cmd_service
	},
	{
		.name = "server",
		.desc = "Set server",
		.args = "-add ip [rip ip] port [rip port]\n-del ip [rip ip] port [rip port]",
		.func = cmd_server
	},
	{
		.name = NULL,
		.desc = NULL,
		.args = NULL,
		.func = NULL
	}
};

int ginit(int argc, char** argv) {
	if(lb_ginit() < 0)
		return -1;
	
	NetworkInterface* ni = ni_get(1);
	ni_config_put(ni, "ip", (void*)(uint64_t)0xc0a86414);	// 192.168.100.20

	return 0;
}

void init(int argc, char** argv) {
	is_continue = true;

	cmd_init();
	lb_init();
}

void destroy() {
}

void gdestroy() {
}

int main(int argc, char** argv) {
	printf("Thread %d booting\n", thread_id());
	if(thread_id() == 0) {
		int err = ginit(argc, argv);
		if(err != 0)
			return err;
	}
	
	thread_barrior();
	
	init(argc, argv);
	
	thread_barrior();

	int count = ni_count();
	while(is_continue) {
		for(int i = 0; i < count; i++) {
			NetworkInterface* ni = ni_get(i);
			if(ni_has_input(ni)) {
				Packet* packet = ni_input(ni);
				lb_process(packet);
			}

		}
		lb_loop();

		char* line = readline();
		if(line != NULL)
			cmd_exec(line, NULL);
	}
	
	thread_barrior();
	
	destroy();
	
	thread_barrior();
	
	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}
	
	return 0;
}
