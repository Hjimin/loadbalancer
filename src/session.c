#include <stdio.h>
#include <malloc.h>
#include <util/map.h>
#include <util/event.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <errno.h>

#include "service.h"
#include "server.h"
#include "session.h"

static bool nat_pack(Session* session, Packet* packet, uint8_t direct);
static bool nat_session_free(Session* session);

static bool dnat_pack(Session* session, Packet* packet, uint8_t direct);
static bool dnat_session_free(Session* session);

static bool dr_pack(Session* session, Packet* packet, uint8_t direct);
static bool dr_session_free(Session* session);

static void session_recharge(Session* session) {
	bool session_free_event(void* context) {
		printf("session free event\n");
		Session* session = context;
		session->event_id = 0;
		session_free(session);

		return false;
	}
	if(session->fin)
		return;

	if(session->event_id != 0)
		event_timer_remove(session->event_id);

	session->event_id = event_timer_add(session_free_event, session, 30000000, 0);
}

Session* session_alloc(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport) {
	Service* service = service_get(ni);
	if(service == NULL)
		return NULL; 

	Interface* service_interface = service->service_interface;
	if(!((protocol == service_interface->protocol) && (daddr == service_interface->addr) && (dport == service_interface->port)))
		return NULL;

	if(service->state != LB_SERVICE_STATE_OK)
		return NULL;
	
	Session* session = malloc(sizeof(Session));
	if(session == NULL) {
		printf("Can'nt allocate Session\n");
		goto error_allocate_session;
	}

	session->service = service;
	session->client_interface = interface_create(protocol, saddr, sport, service->service_interface->ni_num);
	if(session->client_interface == NULL) {
		printf("Interface create error: %d\n", errno);
		goto error_interface_create;
	}

	Server* server = service->get_server(service);
	if(server == NULL) {
		printf("Can'nt get server: %d\n", errno);
		goto error_get_server;
	}
	session->server = server;

	Interface* private_interface = map_get(service->private_interfaces, server->server_interface->ni);
	if(private_interface == NULL) {
		goto error_get_private_interface;
	}

	switch(server->mode) {
		case LB_MODE_NAT:;
			if(protocol == IP_PROTOCOL_TCP)
				session->private_interface = interface_create(private_interface->protocol, private_interface->addr, interface_tcp_port_alloc(private_interface), private_interface->ni_num);
			else if(protocol == IP_PROTOCOL_UDP) {
				session->private_interface = interface_create(private_interface->protocol, private_interface->addr, interface_udp_port_alloc(private_interface), private_interface->ni_num);
			}
			printf("here\n");
			session->loadbalancer_pack = nat_pack;
			session->session_free = nat_session_free;
			break;
		case LB_MODE_DNAT:
			session->private_interface = interface_create(protocol, saddr, sport, private_interface->ni_num);
			session->loadbalancer_pack = dnat_pack;
			session->session_free = dnat_session_free;
			break;
		case LB_MODE_DR:
			session->loadbalancer_pack = dr_pack;
			session->session_free = dr_session_free;
			break;
		default:
			printf("error\n");
			return NULL;
	}

	session->fin = false;

	Map* sessions = ni_config_get(service->service_interface->ni, "pn.lb.sessions");
	if(!map_put(sessions, (void*)((uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport), session)) {
		printf("error session map put1\n");
		goto error_session_map_put1;
	}

	sessions = ni_config_get(server->server_interface->ni, "pn.lb.sessions");
	uint64_t key2 = (uint64_t)session->private_interface->protocol << 48 | (uint64_t)session->private_interface->addr << 16 | (uint64_t)session->private_interface->port;
	if(!map_put(sessions, (void*)key2, session)) {
		printf("error session map put2\n");
		goto error_session_map_put2;
	}

	if(!map_put(server->sessions, (void*)key2, session)) {
		printf("error session map put3\n");
		goto error_session_map_put3;
	}


	session_recharge(session);
	
	return session;

error_session_map_put3:
error_session_map_put2:
error_session_map_put1:
error_get_private_interface:
error_get_server:
error_interface_create:
	free(session);
error_allocate_session:

	return NULL;
}

Session* session_get_from_service(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport) {
	printf("session get from service\n");
	Map* sessions = ni_config_get(ni, "pn.lb.sessions");
	Session* session = map_get(sessions, (void*)((uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport));

	if(session != NULL)
		session_recharge(session);

	return session;
}

bool session_free(Session* session) {
	printf("session free\n");
	if(session->event_id != 0) {
		event_timer_remove(session->event_id);
		session->event_id = 0;
	}

	Map* sessions = ni_config_get(session->client_interface->ni, "pn.lb.sessions");
	if(!map_remove(sessions, (void*)((uint64_t)session->client_interface->protocol << 48 | (uint64_t)session->client_interface->addr << 16 | (uint64_t)session->client_interface->port))) {
		printf("Can'nt remove session from servers\n");
		goto error_session_free1;
	}

	Interface* private_interface = session->private_interface;
	sessions = ni_config_get(private_interface->ni, "pn.lb.sessions");
	uint64_t key = (uint64_t)private_interface->protocol << 48 | (uint64_t)private_interface->addr << 16 | (uint64_t)private_interface->port;
	if(!map_remove(sessions, (void*)key)) {
		printf("Can'nt remove session from private ni\n");
		goto error_session_free2;
	}

	if(!map_remove(session->server->sessions, (void*)key)) {
		printf("Can'nt remove session from servers\n");
		goto error_session_free3;
	}

	printf("hello\n");
	server_is_remove_grace(session->server);
	service_is_remove_grace(session->service);
	printf("world\n");

	session->session_free(session);
	printf("aaaaaaaaa\n");

	free(session);
	printf("qwer\n");

	return true;

error_session_free3:
error_session_free2:
error_session_free1:
	printf("asdf\n");
	return false;
}

Session* session_get_from_server(NetworkInterface* ni, uint8_t protocol, uint32_t daddr, uint16_t dport) {
	Map* sessions = ni_config_get(ni, "pn.lb.sessions");
	uint64_t key = ((uint64_t)protocol << 48 | (uint64_t)daddr << 16 | (uint64_t)dport);

	Session* session = map_get(sessions, (void*)key);

	if(session != NULL) {
		session_recharge(session);
	}

	return session;
}

bool session_set_fin(Session* session) {
	bool gc(void* context) {
		Session* session = context;
		
		printf("Timeout fin\n");
		session_free(session);
		
		return false;
	}
		
	printf("session set fin\n");
	if(session->event_id)
		event_timer_remove(session->event_id);

	session->fin = true;
	session->event_id = event_timer_add(gc, session, 3000, 3000);
	if(session->event_id == 0) {
		printf("Can'nt add service\n");
		return false;
	}
	
	return true;
}

static bool nat_session_free(Session* session) {
	Interface* private_interface = session->private_interface;
	switch(private_interface->protocol) {
		case IP_PROTOCOL_TCP:
			printf("here?\n");
			interface_tcp_port_free(private_interface, private_interface->port);
			printf("here end\n");
			break;
		case IP_PROTOCOL_UDP:
			interface_udp_port_free(private_interface, private_interface->port);
			break;
	}

	return true;
}

static bool dnat_session_free(Session* session) {
	//do nothing
	return true;
}

static bool dr_session_free(Session* session) {
	//do nothing
	return true;
}

static bool nat_pack(Session* session, Packet* packet, uint8_t direct) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	
	Interface* server_interface = session->server->server_interface;
	Interface* service_interface = session->service->service_interface;
	uint8_t protocol = ip->protocol;
	switch(direct) {
		case SESSION_IN:
			switch(protocol) {
				case IP_PROTOCOL_TCP:
					;
					TCP* tcp = (TCP*)ip->body;

					ether->smac = endian48(server_interface->ni->mac);
					ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));
					ip->source = endian32(session->private_interface->addr);
					ip->destination = endian32(server_interface->addr);
					tcp->source = endian16(session->private_interface->port);
					tcp->destination = endian16(server_interface->port);

					tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
					if(session->fin && tcp->ack) {
						if(session->event_id != 0) {
							event_timer_remove(session->event_id);
							session->event_id = 0;
						}
						session_free(session);
					}
					return true;
				case IP_PROTOCOL_UDP:;
					UDP* udp = (UDP*)ip->body;

					ether->smac = endian48(server_interface->ni->mac);
					ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));
					ip->source = endian32(session->private_interface->addr);
					ip->destination = endian32(server_interface->addr);
					udp->source = endian16(session->private_interface->port);
					udp->destination = endian16(server_interface->port);

					udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

					return true;
			}
		case SESSION_OUT:
			switch(protocol) {
				case IP_PROTOCOL_TCP:;
					TCP* tcp = (TCP*)ip->body;

					ether->smac = endian48(service_interface->ni->mac);
					ether->dmac = endian48(arp_get_mac(session->client_interface->ni, session->client_interface->addr));
					ip->source = endian32(service_interface->addr);
					ip->destination = endian32(session->client_interface->addr);
					tcp->source = endian16(service_interface->port);
					tcp->destination = endian16(session->client_interface->port);

					tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
					if(tcp->fin) {
						session_set_fin(session);
					}
					return true;
				case IP_PROTOCOL_UDP:;
					UDP* udp = (UDP*)ip->body;

					ether->smac = endian48(service_interface->ni->mac);
					ether->dmac = endian48(arp_get_mac(session->client_interface->ni, session->client_interface->addr));
					ip->source = endian32(service_interface->addr);
					ip->destination = endian32(server_interface->addr);
					udp->source = endian16(service_interface->addr);
					udp->destination = endian16(server_interface->port);

					udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);
					return true;
			}
	}

	return false;
}

static bool dnat_pack(Session* session, Packet* packet, uint8_t direct) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
		
	Interface* server_interface = session->server->server_interface;
	Interface* service_interface = session->service->service_interface;
	uint8_t protocol = ip->protocol;
	switch(direct) {
		case SESSION_IN:
			switch(protocol) {
				case IP_PROTOCOL_TCP:;
					TCP* tcp = (TCP*)ip->body;
					ether->smac = endian48(server_interface->ni->mac);
					ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));

					ip->destination = endian32(server_interface->addr);
					tcp->destination = endian16(server_interface->port);

					tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
					if(session->fin && tcp->ack) {
						event_timer_remove(session->event_id);
						session_free(session);
					}
					return true;
				case IP_PROTOCOL_UDP:;
					UDP* udp = (UDP*)ip->body;
					ether->smac = endian48(server_interface->ni->mac);
					ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));

					ip->destination = endian32(server_interface->addr);
					udp->destination = endian16(server_interface->port);

					udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);
					return true;
			}
		case SESSION_OUT:
			switch(protocol) {
				case IP_PROTOCOL_TCP:;
					TCP* tcp = (TCP*)ip->body;
					ether->smac = endian48(service_interface->ni->mac);
					ether->dmac = endian48(arp_get_mac(service_interface->ni, endian32(ip->destination)));
					ip->source = endian32(service_interface->addr);
					tcp->source = endian16(service_interface->port);
						
					if(tcp->fin) {
						session_set_fin(session);
					}
					tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
					return true;
				case IP_PROTOCOL_UDP:;
					UDP* udp = (UDP*)ip->body;
					ether->smac = endian48(service_interface->ni->mac);
					ether->dmac = endian48(arp_get_mac(service_interface->ni, endian32(ip->destination)));
					ip->source = endian32(service_interface->addr);
					udp->source = endian16(service_interface->port);

					udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);
					return true;
			}
	}

	return false;
}

static bool dr_pack(Session* session, Packet* packet, uint8_t direct) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);

	Interface* server_interface = session->server->server_interface;
	ether->smac = endian48(server_interface->ni->mac);
	ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));

	return true;
}
