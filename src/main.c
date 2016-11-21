#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <thread.h>
#include <net/ip.h>
#include <util/cmd.h>
#include <util/types.h>
#include <util/event.h>
#include <net/dhcp.h>
#include <readline.h>

#include "endpoint.h"
#include "service.h"
#include "server.h"
#include "schedule.h"
#include "loadbalancer.h"

static bool is_continue;

typedef struct {
	Endpoint private_endpoint;
	Service* service;
} DHCPCallbackData;

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
	bool is_exit_ok(void* context) {
		if(lb_is_all_destroied()) {
			is_continue = false;
			return false;
		}
		return true;
	}
	if(argc == 1) {
		lb_remove(0);
		event_idle_add(is_exit_ok, NULL);
		return 0;
	}

	bool is_force = false;
	uint64_t wait = 0;
	int i = 1;
	for(; i < argc; i++) {
		if(!strcmp(argv[i], "-f")) {
			is_continue = false;
		} else if(!strcmp(argv[i], "-w")) {
			i++;
			if(is_uint64(argv[i]))
				wait = parse_uint64(argv[i]);
			else {
				printf("Wait time number wrong\n");
				return i;
			}

			continue;
		} else {
			printf("Wrong arguments\n");
			return -1;
		}
	}

	if(is_force) {
		lb_remove_force();
		is_continue = false;
	} else {
		lb_remove(wait);
		event_idle_add(is_exit_ok, NULL);
	}

	return 0;
}

bool private_ip_offered(NIC* nic, uint32_t transaction_id, uint32_t ip, void* data) {
	printf(" private ip offered. \n");
	return true;
}

bool private_ip_acked(NIC* nic, uint32_t transaction_id, uint32_t ip, void* _data) {
	printf("private ip leased. \n");
	DHCPCallbackData* data = (DHCPCallbackData*)_data;

	Endpoint private_endpoint = data->private_endpoint;
	private_endpoint.addr = ip; 

	Service* service = data->service;
	service_add_private_addr(service, &private_endpoint);

	if(!service)
		return false;

	return true;
}

static int cmd_service(int argc, char** argv, void(*callback)(char* result, int exit_status)) {

	if(strcmp(argv[1], "list") != 0 && argc != 10) {
		printf("not enough argument for service command \n"); 
		return -1;
	}

	if(!strcmp(argv[1], "add")) {
		int i = 2;
		Service* service = NULL;

	//	Endpoint service_endpoint;
//		Endpoint private_endpoint;

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
					service_endpoint.ni = nic_get(ni_num);
					service_endpoint.ni_num = ni_num;
					if(!service_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}

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
					service_endpoint.ni = nic_get(ni_num);
					service_endpoint.ni_num = ni_num;
					if(!service_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}

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
				else if(!strcmp(argv[i], "d"))
					schedule = SCHEDULE_DESTINATION_IP_HASH;
				else if(!strcmp(argv[i], "w"))
					schedule = SCHEDULE_WEIGHTED_ROUND_ROBIN;
				else
					return i;

				service_set_schedule(service, schedule);
				continue;
			} else if(!strcmp(argv[i], "-out") && !!service) {
				i++;

				Endpoint private_endpoint;
				if(!strncmp(argv[i], "dhcp", 4)) {
					private_endpoint.addr = 0;
					private_endpoint.port = 0;
				} else {
					private_endpoint.addr = str_to_addr(argv[i]);
					private_endpoint.port = 0;
				}
				i++;
				if(is_uint8(argv[i])) {
					uint8_t ni_num = parse_uint8(argv[i]);
					private_endpoint.ni = nic_get(ni_num);
					private_endpoint.ni_num = ni_num;
					if(!private_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}

				//service_add_private_addr(service, &private_endpoint);
				if(private_endpoint.addr != 0 ) {
					service_add_private_addr(service, &private_endpoint);
				} else if (private_endpoint.addr == 0) {
					DHCPCallbackData* data = malloc(sizeof(DHCPCallbackData));
					data->service = service;
					data->private_endpoint = private_endpoint;
					dhcp_lease_ip(private_endpoint.ni, private_ip_offered, private_ip_acked, data); 
				}

				continue;
			} else { 
				printf("Wrong arguments\n");
				return i;
			}
		}


//		if(service == NULL) {
//			printf("Can'nt create service\n");
//			return -1;
//		}

		return 0;

	} else if(!strcmp(argv[1], "delete")) {
		int i = 2;
		bool is_force = false;
		uint64_t wait = 0;
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
					service_endpoint.ni = nic_get(ni_num);
					service_endpoint.ni_num = ni_num;
					if(!service_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}

				service = service_get(&service_endpoint);
				if(!service) {
					printf("Can'nt found service\n");
					return i;
				}

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
					service_endpoint.ni = nic_get(ni_num);
					service_endpoint.ni_num = ni_num;
					if(!service_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}

				service = service_get(&service_endpoint);
				if(!service) {
					printf("Can'nt found service\n");
					return i;
				}

				continue;
			} else if(!strcmp(argv[i], "-f")) {
				is_force = true;
				continue;
			} else if(!strcmp(argv[i], "-w")) {
				i++;
				if(is_uint64(argv[i]))
					wait = parse_uint64(argv[i]);
				else {
					printf("Wait time number wrong\n");
					return i;
				}

				continue;
			} else {
				printf("Wrong arguments\n");
				return i;
			}
		}

		if(!service) {
			printf("Can'nt found service\n");
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
	} else {
		printf("Unknown Command\n");
		return -1;
	}



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
					server_endpoint.ni = nic_get(ni_num);
					server_endpoint.ni_num = ni_num;
					if(!server_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						 return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}

				server = server_alloc(&server_endpoint);
				if(!server) {
					printf("Can'nt allocate server\n");
					return i;
				}

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
					server_endpoint.ni = nic_get(ni_num);
					server_endpoint.ni_num = ni_num;
					if(!server_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}


				server = server_alloc(&server_endpoint);
				if(!server) {
					printf("Can'nt allocate server\n");
					return i;
				}

				continue;
			} else if(!strcmp(argv[i], "-m") && !!server) {
				i++;
				uint8_t mode;
				if(!strcmp(argv[i], "nat")) {
					mode = MODE_NAT;
				} else if(!strcmp(argv[i], "dnat")) {
					mode = MODE_DNAT;
				} else if(!strcmp(argv[i], "dr")) {
					mode = MODE_DR;
				} else {
					printf("Mode type wrong\n");
					return i;
				}

				if(!server_set_mode(server, mode)) {
					printf("Can'nt set Mode\n");
					return i;
				}
			} else if(!strcmp(argv[i], "-w") && !!server) {
				i++;
				if(is_uint8(argv[i])) {
					uint8_t weight = parse_uint8(argv[i]);
					server_set_weight(server, weight);
				} else {
					printf("Weight numbe wrong\n");
					return i;
				}
			} else {
				printf("Wrong arguments\n");
				return i;
			}
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
					server_endpoint.ni = nic_get(ni_num);
					server_endpoint.ni_num = ni_num;
					if(!server_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}

				server = server_get(&server_endpoint);
				if(!server) {
					printf("Can'nt get server\n");
					return i;
				}

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
					server_endpoint.ni = nic_get(ni_num);
					server_endpoint.ni_num = ni_num;
					if(!server_endpoint.ni) {
						printf("Netowrk Interface number wrong\n");
						 return i;
					}
				} else {
					printf("Netowrk Interface number wrong\n");
					return i;
				}

				server = server_get(&server_endpoint);
				if(!server) {
					printf("Can'nt get server\n");
					return i;
				}

				continue;
			} else if(!strcmp(argv[i], "-f")) {
				is_force = true;
				continue;
			} else if(!strcmp(argv[i], "-w")) {
				i++;
				if(is_uint64(argv[i]))
					wait = parse_uint64(argv[i]);
				else {
					printf("Wait time number wrong\n");
					return i;
				}

				continue;
			} else {
				printf("Wrong arguments\n");
				return i;
			}
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
	} else {
		printf("Unknown Command\n");
		return -1;
	}

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
		.desc = "Add service, Delete Service, Dump service list",
		.args = "\tadd [Protocol Public Address:Port][-s Schedule] [-out [Private Address] [Private Port]]\n \
			\tdelete [Protocol Public Address:Port]\n \
			\tlist\n",
		.func = cmd_service
	},
	{
		.name = "server",
		.desc = "Add server, Delete server, Dump server list",
		.args = "\tadd [[Protocol] [Server Address]:[Port]][-m nat type]\n \
			\tdelete [[Protocol] [Server Address]:[Port]]\n \
			\tlist\n",
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
	uint32_t i;
	uint32_t count = nic_count();

	if(lb_ginit() < 0)
		return -1;

  	for(i=0; count > i; i++) {
		NIC* nic = nic_get(i);
                dhcp_init(nic);
                printf("dhcp_init\n");
        }
	return 0;
}

void init(int argc, char** argv) {
	is_continue = true;

	event_init();
	cmd_init();
}

void destroy() {
	lb_destroy();
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

	int count = nic_count();
	while(is_continue) {
		for(int i = 0; i < count; i++) {
			NIC* ni = nic_get(i);
			if(nic_has_input(ni)) {
				Packet* packet = nic_input(ni);
				if(!packet)
					continue;

				if(!lb_process(packet, i))
					nic_free(packet);
			}
		}
		event_loop();

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
