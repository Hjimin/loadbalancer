#include <malloc.h>
#include <net/ni.h>

#include "interface.h"

Interface* interface_create(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t ni_num) {
	NetworkInterface* ni = ni_get(ni_num);
	if(ni == NULL)
		return NULL;

	Interface* interface = malloc(sizeof(Interface));
	if(interface == NULL)
		return NULL;

	interface->protocol = protocol;
	interface->addr = addr;
	interface->port = port;
	interface->ni = ni;
	interface->ni_num = ni_num;

	interface->tcp_ports = NULL;
	interface->tcp_next_port = 0;
	interface->udp_ports = NULL;
	interface->udp_next_port = 0;

	return interface;
}

void interface_delete(Interface* interface) {
	free(interface);
}

uint16_t interface_tcp_port_alloc(Interface* interface) {
	Map* ports = interface->tcp_ports;
	if(!ports) {
		ports = map_create(4096, NULL, NULL, NULL);
		interface->tcp_ports = ports;
	}
	
	uint16_t port = interface->tcp_next_port;

	if(port < 49152)
		port = 49152;
	
	while(map_contains(ports, (void*)(uint64_t)port)) {
		if(++port < 49152)
			port = 49152;
	}	
	
	map_put(ports, (void*)(uint64_t)port, (void*)(uint64_t)port);
	interface->tcp_next_port = port + 1;
	
	return port;
}

void interface_tcp_port_free(Interface* interface, uint16_t port) {
	Map* ports = interface->tcp_ports;
	if(!ports)
		return;
	
	map_remove(ports, (void*)(uint64_t)port);
}

uint16_t interface_udp_port_alloc(Interface* interface) {
	Map* ports = interface->udp_ports;
	if(!ports) {
		ports = map_create(4096, NULL, NULL, NULL);
		interface->udp_ports = ports;
	}
	
	uint16_t port = interface->udp_next_port;
	if(port < 49152)
		port = 49152;
	
	while(map_contains(ports, (void*)(uint64_t)port)) {
		if(++port < 49152)
			port = 49152;
	}	
	
	map_put(ports, (void*)(uint64_t)port, (void*)(uint64_t)port);
	interface->udp_next_port = port + 1;
	
	return port;
}

void interface_udp_port_free(Interface* interface, uint16_t port) {
	Map* ports = interface->udp_ports;
	if(!ports)
		return;
	
	map_remove(ports, (void*)(uint64_t)port);
}
