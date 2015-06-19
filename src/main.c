#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <thread.h>
#include <net/ip.h>
#include <util/cmd.h>
#include <util/types.h>
#include <readline.h>

#include "service.h"
#include "server.h"
#include "loadbalancer.h"

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
		uint8_t ni_in = 0;
		uint8_t ni_out[16];
		uint8_t ni_out_count;

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
			} else if(!strcmp(argv[i], "-in")) {
				i++;
				if(is_uint8(argv[i]))
					ni_in = parse_uint8(argv[i]);
				else
					return i;

				continue;
			} else if(!strcmp(argv[i], "-out")) {
				i++;
				if(is_uint64(argv[i]))
					ni_out[ni_out_count++] = parse_uint64(argv[i]);
				else
					return i;

				continue;
			} else
				return i;
		}
			
		service_add(protocol, addr, port, schedule, ni_in, ni_out, ni_out_count);

		return 0;
	} else if(!strcmp(argv[1], "delete")) {
		int i = 2;
		bool is_force = false;
		uint8_t protocol = 0;
		uint32_t addr = 0;
		uint16_t port = 0;
		uint64_t wait = 0;
		uint8_t ni_in = 0;
		NetworkInterface* ni = NULL;

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
			} else if(!strcmp(argv[i], "-in")) {
				i++;
				if(is_uint8(argv[i])) {
					ni_in = parse_uint8(argv[i]);
					ni = ni_get(ni_in);
				} else
					return i;

				continue;
			} else if(!strcmp(argv[i], "-f")) {
				is_force = true;
				continue;
			} else
				return i;
		}

		if(ni == NULL) {
			printf("Can'nt found NetworkInterface\n");
			return -1;
		}

		Service* service = service_found(ni, protocol, addr, port);
		if(service == NULL) {
			printf("Can'nt found Service\n");
			return -1;
		}

		if(!is_force)
			service_remove(service, wait); //grace
		else
			service_remove_force(service);

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
		uint32_t server_addr = 0;
		uint16_t server_port = 0;
		uint8_t mode = LB_MODE_NAT; //DEFAULT
		uint8_t ni_num = 0;

		void set_addr_port() {
			server_addr = str_to_adr(argv[i]);
			server_port = str_to_port(argv[i]);
		}
		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t")) {
				i++;
				protocol = IP_PROTOCOL_TCP;
				set_addr_port();
				continue;
			} else if(!strcmp(argv[i], "-u")) {
				i++;
				protocol = IP_PROTOCOL_UDP;
				set_addr_port();
				continue;
			} else if(!strcmp(argv[i], "-p")) {
				i++;
				if(is_uint8(argv[i]))
					ni_num = parse_uint8(argv[i]);
				else
					return i;
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

		if(!server_add(protocol, server_addr, server_port, mode, ni_num)) {
			printf("Can'nt add server\n");
			return -1;
		}

		return 0;
	} else if(!strcmp(argv[1], "delete")) {
		int i = 2;
		uint8_t protocol = 0;
		uint32_t server_addr = 0;
		uint16_t server_port = 0;
		uint8_t ni_num = 0;
		bool is_force = false;
		uint64_t wait = 0; //wait == 0 ;wait to disconnect all session.

		void set_addr_port() {
			server_addr = str_to_adr(argv[i]);
			server_port = str_to_port(argv[i]);
		}
		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t")) {
				i++;
				protocol = IP_PROTOCOL_TCP;
				set_addr_port();
				continue;
			} else if(!strcmp(argv[i], "-u")) {
				i++;
				protocol = IP_PROTOCOL_UDP;
				set_addr_port();
				continue;
			} else if(!strcmp(argv[i], "-p")) {
				i++;
				if(!is_uint8(argv[i]))
					return i;

				ni_num = parse_uint8(argv[i]);
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
		Server* server = server_found(protocol, server_addr, server_port, ni_num);
		if(server == NULL) {
			printf("Can'nt found server\n");
			return -1;
		}
		bool result;
		if(is_force) {
			result = server_remove_force(server);
		} else {
			result = server_remove(server, wait);
		}

		if(!result)
			printf("Delete fail\n");

		return 0;
	} else if(!strcmp(argv[1], "list")) {
		server_dump();
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
		.name = "help",
		.desc = "Show this message",
		.func = cmd_help
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
				if(packet != NULL)
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
