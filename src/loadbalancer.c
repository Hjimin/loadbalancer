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

	return 0;
}

int lb_init() {
	event_init();
	return 0;
}

void lb_loop() {
	event_loop();
}

bool lb_process(Packet* packet) {
	if(arp_process(packet))
		return true;
	
	if(icmp_process(packet))
		return true;
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		
		uint8_t protocol = ip->protocol;
		uint32_t saddr = endian32(ip->source);
		uint32_t daddr = endian32(ip->destination);
		uint16_t sport;
		uint16_t dport;

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

		//Service
		Session* session = service_get_session(packet->ni, protocol, saddr, sport);
		if(!session) {
			session = service_alloc_session(packet->ni, protocol, saddr, sport, daddr, dport);
		}
		
		if(session) {
			NetworkInterface* server_ni = session->server_endpoint->ni;
			session->translate(session, packet);
			ni_output(server_ni, packet);
			return true;
		}

		//Server
		session = server_get_session(packet->ni, protocol, daddr, dport);
		if(session) {
			NetworkInterface* service_ni = session->service_endpoint->ni;
			session->untranslate(session, packet);
			ni_output(service_ni, packet);
			return true;
		}
		return false;
	}

	return false;
}
