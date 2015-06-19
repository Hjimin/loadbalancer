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

int lb_ginit() {
	uint32_t count = ni_count();
	if(count < 2)
		return -1;

	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		Map* services = map_create(4096, NULL, NULL, NULL);
		if(services == NULL)
			return -1;
		ni_config_put(ni, "pn.lb.services", services);
		Map* servers = map_create(4096, NULL, NULL, NULL);
		if(servers == NULL)
			return -1;
		ni_config_put(ni, "pn.lb.servers", servers);
		arp_announce(ni, 0);
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

	if(service_is_empty(ni))
		return false;
	
	if(service_arp_process(packet))
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
		if(protocol == IP_PROTOCOL_TCP) {
			TCP* tcp = (TCP*)ip->body;
			sport = endian16(tcp->source);
			dport = endian16(tcp->destination);

			Session* session = session_get(ni, protocol, saddr, sport, daddr, dport);
			if(!session) {
				session = session_alloc(ni, protocol, saddr, sport, daddr, dport);
			}
		
			if(session) {
				switch(session->server->mode) {
					case LB_MODE_NAT:
						ip->source = endian32(session->v_addr);
						ip->destination = endian32(session->server->addr);
						tcp->source = endian16(session->v_port);
						tcp->destination = endian16(session->server->port);
					
						ether->smac = endian48(session->server->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->server->ni, session->server->addr));
						break;

					case LB_MODE_DNAT:
						ip->destination = endian32(session->server->addr);
						tcp->destination = endian16(session->server->port);

						ether->smac = endian48(session->server->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->server->ni, session->server->addr));
						break;

					case LB_MODE_DR:
						ether->smac = endian48(session->server->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->server->ni, session->server->addr));
						break;
				}

				tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
				ni_output(session->server->ni, packet);
				if(session->fin && tcp->ack) {
					event_timer_remove(session->event_id);
					session_free(session);
				}
				return true;
			}
		} else if(protocol == IP_PROTOCOL_UDP) {
			UDP* udp = (UDP*)ip->body;
			sport = endian16(udp->source);
			dport = endian16(udp->destination);

			Session* session = session_get(ni, protocol, saddr, sport, daddr, dport);
			if(!session) {
				session = session_alloc(ni, protocol, saddr, sport, daddr, dport);
			}

			if(session) {
				switch(session->server->mode) {
					case LB_MODE_NAT:
						ip->source = endian32(session->v_addr);
						ip->destination = endian32(session->server->addr);
						udp->source = endian16(session->v_port);
						udp->destination = endian16(session->server->port);
					
						ether->smac = endian48(session->server->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->server->ni, session->server->addr));
						break;

					case LB_MODE_DNAT:
						ip->destination = endian32(session->server->addr);
						udp->destination = endian16(session->server->port);
						
						ether->smac = endian48(session->server->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->server->ni, session->server->addr));
						break;

					case LB_MODE_DR:
						ether->smac = endian48(session->server->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->server->ni, session->server->addr));
						break;
				}
				udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);
				ni_output(session->server->ni, packet);
				return true;
			}
		}
	}

	return false;
}

static bool process_server(Packet* packet) {
	NetworkInterface* ni = packet->ni;
	
	if(server_is_empty(ni))
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
		if(protocol == IP_PROTOCOL_TCP) {
			TCP* tcp = (TCP*)ip->body;
			sport = endian16(tcp->source);
			dport = endian16(tcp->destination);

			Session* session;
			if(daddr == (uint32_t)(uint64_t)ni_config_get(ni, "ip")) {
				//NAT
				session = session_get_nat(ni, protocol, saddr, sport, daddr, dport);
			} else {
				//DNAT
				session = session_get_dnat(ni, protocol, saddr, sport, daddr, dport);
			}

			if(session) {
				switch(session->server->mode) {
					case LB_MODE_NAT:
						ip->source = endian32(session->service->addr);
						ip->destination = endian32(session->s_addr);
						tcp->source = endian16(session->service->port);
						tcp->destination = endian16(session->s_port);
						ether->smac = endian48(session->service->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->service->ni, endian32(ip->destination)));
						break;

					case LB_MODE_DNAT:
						ip->source = endian32(session->service->addr);
						tcp->source = endian16(session->service->port);
							
						ether->smac = endian48(session->service->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->service->ni, endian32(ip->destination)));
						break;

					case LB_MODE_DR:
						//Do nothing
						break;
				}

				tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);

				ni_output(session->service->ni, packet);
				if(tcp->fin) {
					session_set_fin(session);
				}
				return true;
			}
		} else if(protocol == IP_PROTOCOL_UDP) {
			UDP* udp = (UDP*)ip->body;
			sport = endian16(udp->source);
			dport = endian16(udp->destination);

			Session* session;
			if(daddr == (uint32_t)(uint64_t)ni_config_get(ni, "ip")) {
				//NAT
				session = session_get_nat(ni, protocol, saddr, sport, daddr, dport);
			} else {
				//DNAT
				session = session_get_dnat(ni, protocol, saddr, sport, daddr, dport);
			}

			if(session) {
				uint32_t addr = (uint32_t)(uint64_t)ni_config_get(session->service->ni, "ip");
				uint16_t port = (uint16_t)(uint64_t)ni_config_get(session->service->ni, "pn.lb.port");
					
				switch(session->server->mode) {
					case LB_MODE_NAT:
						ip->source = endian32(addr);
						ip->destination = endian32(session->server->addr);
						udp->source = endian16(port);
						udp->destination = endian16(session->server->port);

						ether->smac = endian48(session->service->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->service->ni, endian32(ip->destination)));
						break;

					case LB_MODE_DNAT:
						ip->source = endian32(addr);
						udp->source = endian16(port);

						ether->smac = endian48(session->service->ni->mac);
						ether->dmac = endian48(arp_get_mac(session->service->ni, endian32(ip->destination)));
						break;

					case LB_MODE_DR:
						//Do nothing
						break;
				}

				udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);
				ni_output(session->service->ni, packet);
				return true;
			}
		}
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
