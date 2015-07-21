#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <thread.h>
#include <net/ip.h>
#include <util/cmd.h>
#include <util/types.h>
#include <readline.h>

#include "endpoint.h"
#include "service.h"
#include "server.h"
#include "schedule.h"
#include "loadbalancer.h"

static bool is_continue;

static uint32_t str_to_addr(char* argv) {
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
		Service* service = NULL;

		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t") && !service) {
				i++;
				Endpoint service_endpoint;
				service_endpoint.protocol = IP_PROTOCOL_TCP;
				service_endpoint.addr = str_to_addr(argv[i]);
				service_endpoint.port = str_to_port(argv[i]);
				i++;

				if(is_uint8(argv[i])) {
					 uint8_t ni_num = parse_uint8(argv[i]);
					service_endpoint.ni = ni_get(ni_num);
					if(!service_endpoint.ni)
						 return i;
				} else
					return i;

				service = service_alloc(&service_endpoint);
				if(!service)
					return i;

				continue;
			} else if(!strcmp(argv[i], "-u") && !service) {
				i++;
				Endpoint service_endpoint;
				service_endpoint.protocol = IP_PROTOCOL_UDP;
				service_endpoint.addr = str_to_addr(argv[i]);
				service_endpoint.port = str_to_port(argv[i]);
				i++;

				if(is_uint8(argv[i])) {
					uint8_t ni_num = parse_uint8(argv[i]);
					service_endpoint.ni = ni_get(ni_num);
					if(!service_endpoint.ni)
						 return i;
				} else
					return i;

				service = service_alloc(&service_endpoint);
				if(!service)
					return i;

				continue;
			} else if(!strcmp(argv[i], "-s") && !!service) {
				i++;

				uint8_t schedule;
				if(!strcmp(argv[i], "rr"))
					schedule = SCHEDULE_ROUND_ROBIN;
				else if(!strcmp(argv[i], "r"))
					schedule = SCHEDULE_RANDOM;
				else if(!strcmp(argv[i], "l"))
					schedule = SCHEDULE_LEAST;
				else if(!strcmp(argv[i], "h"))
					schedule = SCHEDULE_SOURCE_IP_HASH;
				else if(!strcmp(argv[i], "w"))
					schedule = SCHEDULE_WEIGHTED_ROUND_ROBIN;
				else
					return i;

				service_set_schedule(service, schedule);
				continue;
			} else if(!strcmp(argv[i], "-out") && !!service) {
				i++;
				Endpoint private_endpoint;
				private_endpoint.addr = str_to_addr(argv[i]);
				private_endpoint.port = 0;
				i++;
				if(is_uint8(argv[i])) {
					 uint8_t ni_num = parse_uint8(argv[i]);
					 private_endpoint.ni = ni_get(ni_num);
					 if(!private_endpoint.ni)
						 return i;
				} else
					return i;

				service_add_private_addr(service, &private_endpoint);
				continue;
			} else
				return i;
		}
			
		if(service == NULL) {
			printf("Can'nt create service\n");
			return -1;
		}

		return 0;
	} else if(!strcmp(argv[1], "delete")) {
		int i = 2;
		bool is_force = false;
		uint64_t wait = 0;
		Service* service = NULL;

		i++;
		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t") && !service) {
				i++;
				Endpoint service_endpoint;
				service_endpoint.protocol = IP_PROTOCOL_TCP;
				service_endpoint.addr = str_to_addr(argv[i]);
				service_endpoint.port = str_to_port(argv[i]);
				i++;

				if(is_uint8(argv[i])) {
					 uint8_t ni_num = parse_uint8(argv[i]);
					service_endpoint.ni = ni_get(ni_num);
					 if(!service_endpoint.ni)
						 return i;
				} else
					return i;

				service = service_get(&service_endpoint);
				if(!service)
					return i;

				continue;
			} else if(!strcmp(argv[i], "-u") && !service) {
				i++;
				Endpoint service_endpoint;
				service_endpoint.protocol = IP_PROTOCOL_UDP;
				service_endpoint.addr = str_to_addr(argv[i]);
				service_endpoint.port = str_to_port(argv[i]);
				i++;

				if(is_uint8(argv[i])) {
					 uint8_t ni_num = parse_uint8(argv[i]);
					service_endpoint.ni = ni_get(ni_num);
					 if(!service_endpoint.ni)
						 return i;
				} else
					return i;

				service = service_get(&service_endpoint);
				if(!service)
					return i;

				continue;
			} else if(!strcmp(argv[i], "-f")) {
				is_force = true;
				continue;
			} else
				return i;
		}

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
		Server* server = NULL;

		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t") && !server) {
				i++;
				Endpoint server_endpoint;
				server_endpoint.protocol = IP_PROTOCOL_TCP;
				server_endpoint.addr = str_to_addr(argv[i]);
				server_endpoint.port = str_to_port(argv[i]);
				i++;

				if(is_uint8(argv[i])) {
					uint8_t ni_num = parse_uint8(argv[i]);
					server_endpoint.ni = ni_get(ni_num);
					if(!server_endpoint.ni)
						 return i;
				} else
					return i;

				server = server_alloc(&server_endpoint);
				if(!server)
					return i;

				continue;
			} else if(!strcmp(argv[i], "-u") && !server) {
				i++;
				Endpoint server_endpoint;
				server_endpoint.protocol = IP_PROTOCOL_UDP;
				server_endpoint.addr = str_to_addr(argv[i]);
				server_endpoint.port = str_to_port(argv[i]);
				i++;

				if(is_uint8(argv[i])) {
					uint8_t ni_num = parse_uint8(argv[i]);
					server_endpoint.ni = ni_get(ni_num);
					if(!server_endpoint.ni)
						 return i;
				} else
					return i;


				server = server_alloc(&server_endpoint);
				if(!server)
					return i;

				continue;
			} else if(!strcmp(argv[i], "-m") && !!server) {
				i++;
				uint8_t mode;
				if(!strcmp(argv[i], "nat")) {
					mode = MODE_NAT;
					continue;
				} else if(!strcmp(argv[i], "dnat")) {
					mode = MODE_DNAT;
					continue;
				} else if(!strcmp(argv[i], "dr")) {
					mode = MODE_DR;
					continue;
				} else
					return i;

				if(!server_set_mode(server, mode))
					return i;
			} else
				return i;
		}

		if(server == NULL) {
			printf("Can'nt add server\n");
			return -1;
		}

		return 0;
	} else if(!strcmp(argv[1], "delete")) {
		int i = 2;
		bool is_force = false;
		uint64_t wait = 0; //wait == 0 ;wait to disconnect all session.
		Server* server = NULL;

		for(;i < argc; i++) {
			if(!strcmp(argv[i], "-t") && !server) {
				i++;
				Endpoint server_endpoint;
				server_endpoint.protocol = IP_PROTOCOL_TCP;
				server_endpoint.addr = str_to_addr(argv[i]);
				server_endpoint.port = str_to_port(argv[i]);
				i++;

				if(is_uint8(argv[i])) {
					uint8_t ni_num = parse_uint8(argv[i]);
					server_endpoint.ni = ni_get(ni_num);
					if(!server_endpoint.ni)
						 return i;
				} else
					return i;

				server = server_alloc(&server_endpoint);
				if(!server)
					return i;

				continue;
			} else if(!strcmp(argv[i], "-u") && !server) {
				i++;
				Endpoint server_endpoint;
				server_endpoint.protocol = IP_PROTOCOL_UDP;
				server_endpoint.addr = str_to_addr(argv[i]);
				server_endpoint.port = str_to_port(argv[i]);
				i++;

				if(is_uint8(argv[i])) {
					uint8_t ni_num = parse_uint8(argv[i]);
					server_endpoint.ni = ni_get(ni_num);
					if(!server_endpoint.ni)
						 return i;
				} else
					return i;

				server = server_alloc(&server_endpoint);
				if(!server)
					return i;

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

		if(server == NULL) {
			printf("Can'nt found server\n");
			return -1;
		}

		if(is_force) {
			server_remove_force(server);
		} else {
			server_remove(server, wait);
		}

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
				if(!packet)
					continue;

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
