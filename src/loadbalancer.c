#include <stdio.h>
#include <util/list.h>
#include <util/event.h>
#include <util/types.h>
#include <net/ni.h>
#include <net/ether.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/arp.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "loadbalancer.h"
#include "service.h"
#include "server.h"
#include "session.h"

extern void* __gmalloc_pool;
int lb_ginit() {
	uint32_t count = ni_count();
	if(count < 2)
		return -1;

	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		Map* sessions = map_create(4096, NULL, NULL, __gmalloc_pool);
		if(sessions == NULL) {
			return -1;
		}
		ni_config_put(ni, PN_LB_SESSIONS, sessions);

		Map* servers = map_create(4096, NULL, NULL, __gmalloc_pool);
		if(servers == NULL) {
			return -1;
		}
		ni_config_put(ni, PN_LB_SERVERS, servers);

		List* private_interfaces = list_create(__gmalloc_pool);
		if(private_interfaces == NULL) {
			return -1;
		}
		ni_config_put(ni, PN_LB_PRIVATE_INTERFACES, private_interfaces);
	}

	return 0;
}

int lb_init() {
	event_init();
	return 0;
}

void lb_loop() {
	event_loop();
}

static bool process_service(Packet* packet) {
	NetworkInterface* ni = packet->ni;

	if(!service_get(ni))
		return false;
	
	if(arp_process(packet))
		return true;
	
	if(icmp_process(packet))
		return true;
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		
		uint8_t protocol;
		uint32_t saddr;
		uint32_t daddr;
		uint16_t sport;
		uint16_t dport;

		protocol = ip->protocol;
		saddr = endian32(ip->source);
		daddr = endian32(ip->destination);
		switch(protocol) {
			case IP_PROTOCOL_TCP:
				;
				TCP* tcp = (TCP*)ip->body;
				sport = endian16(tcp->source);
				dport = endian16(tcp->destination);
				break;
			case IP_PROTOCOL_UDP:
				;
				UDP* udp = (UDP*)ip->body;
				sport = endian16(udp->source);
				dport = endian16(udp->destination);
				break;
			default:
				return false;
		}

		Session* session = service_get_session(ni, protocol, saddr, sport);
		if(!session) {
			session = service_alloc_session(ni, protocol, saddr, sport, daddr, dport);
		}
	
		if(!session)
			return false;

		NetworkInterface* server_ni = session->server_interface->ni;
		session->loadbalancer_pack(session, packet);
		ni_output(server_ni, packet);

		return true;
	}

	return false;
}

static bool process_server(Packet* packet) {
	NetworkInterface* ni = packet->ni;
	
	List* private_interfaces = ni_config_get(ni, PN_LB_PRIVATE_INTERFACES);
	if(list_is_empty(private_interfaces))
		return false;

	if(server_arp_process(packet))
		return true;
	
	if(server_icmp_process(packet))
		return true;
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		
		uint8_t protocol = ip->protocol;
		uint32_t daddr = endian32(ip->destination);
		uint16_t dport;

		switch(protocol) {
			case IP_PROTOCOL_TCP:
				;
				TCP* tcp = (TCP*)ip->body;
				dport = endian16(tcp->destination);
				break;
			case IP_PROTOCOL_UDP:
				;
				UDP* udp = (UDP*)ip->body;
				dport = endian16(udp->destination);
				break;
			default:
				return false;
		}

		Session* session = server_get_session(ni, protocol, daddr, dport);
		if(!session)
			return false;

		NetworkInterface* client_ni = session->client_interface->ni;
		session->loadbalancer_unpack(session, packet);
		ni_output(client_ni, packet);

		return true;
	}
	
	return false;
}

void lb_process(Packet* packet) {
	if(!process_service(packet)) {
		if(!process_server(packet)) {
			ni_free(packet);
		}
	}
}
