#include <stdint.h>
#include <net/ni.h>
#include <net/interface.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include "endpoint.h"

Endpoint* endpoint_alloc(NetworkInterface* ni, uint32_t addr, uint8_t protocol, uint16_t port) {
	if(!ni_ip_get(ni, addr)) { 
		if(!ni_ip_add(ni, addr))
			return NULL;
	}

	if(protocol == IP_PROTOCOL_TCP) {
		if(!tcp_port_alloc0(ni, addr, port))
			goto port_alloc_fail;
	} else if(protocol == IP_PROTOCOL_UDP) {
		if(!udp_port_alloc0(ni, addr, port))
			goto port_alloc_fail;
	}

	Endpoint* endpoint = __malloc(sizeof(Endpoint), ni->pool);
	if(!endpoint)
		goto endpoint_alloc_fail;

	endpoint->ni = ni;
	endpoint->addr = addr;
	endpoint->protocol = protocol;
	endpoint->port = port;

	return endpoint;

endpoint_alloc_fail:
	//port free
	if(endpoint->protocol == IP_PROTOCOL_TCP) {
		tcp_port_free(ni, endpoint->addr, endpoint->port);
	} else if (endpoint->protocol == IP_PROTOCOL_UDP) {
		udp_port_free(ni, endpoint->addr, endpoint->port);
	}

port_alloc_fail:
	;
	//delete if port is empty
	IPv4Interface* interface = ni_ip_get(ni, addr);
	if(set_is_empty(interface->tcp_ports) && set_is_empty(interface->udp_ports)) {
		ni_ip_remove(ni, addr);
	}

	return NULL;
}

bool endpoint_free(NetworkInterface* ni, Endpoint* endpoint) {
	if(endpoint->protocol == IP_PROTOCOL_TCP) {
		tcp_port_free(ni, endpoint->addr, endpoint->port);
	} else if(endpoint->protocol == IP_PROTOCOL_UDP) {
		udp_port_free(ni, endpoint->addr, endpoint->port);
	}

	//delete if port is empty
	IPv4Interface* interface = ni_ip_get(ni, endpoint->addr);
	if(set_is_empty(interface->tcp_ports) && set_is_empty(interface->udp_ports)) {
		ni_ip_remove(ni, endpoint->addr);
	}

	__free(endpoint, ni->pool);

	return true;
}
