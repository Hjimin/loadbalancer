#include <stdio.h>
#include <malloc.h>
#include <util/map.h>
#include <util/event.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "service.h"
#include "server.h"
#include "session.h"

static bool nat_tcp_pack(Session* session, Packet* packet);
static bool nat_udp_pack(Session* session, Packet* packet);
static bool nat_tcp_unpack(Session* session, Packet* packet);
static bool nat_udp_unpack(Session* session, Packet* packet);
static bool nat_tcp_free(Session* session);
static bool nat_udp_free(Session* session);

static bool dnat_tcp_pack(Session* session, Packet* packet);
static bool dnat_udp_pack(Session* session, Packet* packet);
static bool dnat_tcp_unpack(Session* session, Packet* packet);
static bool dnat_udp_unpack(Session* session, Packet* packet);
static bool dnat_free(Session* session);

static bool dr_pack(Session* session, Packet* packet);
static bool dr_unpack(Session* session, Packet* packet);
static bool dr_free(Session* session);

static void session_recharge(Session* session) {
	bool session_free_event(void* context) {
		Session* session = context;
		session->event_id = 0;
		session_free(session);

		return false;
	}
	if(session->fin)
		return;

	if(session->event_id == 0)
		session->event_id = event_timer_add(session_free_event, session, 30000000, 0);
	else
		session->event_id = event_timer_update(session->event_id);

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
		printf("Interface create error\n");
		goto error_interface_create;
	}

	Server* server = service->get_server(service);
	if(server == NULL) {
		printf("Can'nt get server\n");
		goto error_get_server;
	}
	session->server = server;

	Interface* private_interface = map_get(service->private_interfaces, server->server_interface->ni);
	if(private_interface == NULL) {
		goto error_get_private_interface;
	}

	switch(server->mode) {
		case LB_MODE_NAT:
			 switch(protocol) {
				 case IP_PROTOCOL_TCP:
					session->private_interface = interface_create(private_interface->protocol, private_interface->addr, interface_tcp_port_alloc(private_interface), private_interface->ni_num);
					if(session->private_interface == NULL)
						goto error_private_interface_create;

					session->loadbalancer_pack = nat_tcp_pack;
					session->loadbalancer_unpack = nat_tcp_unpack;
					session->session_free = nat_tcp_free;
					 break;
				 case IP_PROTOCOL_UDP:
					session->private_interface = interface_create(private_interface->protocol, private_interface->addr, interface_udp_port_alloc(private_interface), private_interface->ni_num);
					if(session->private_interface == NULL)
						goto error_private_interface_create;

					session->loadbalancer_pack = nat_udp_pack;
					session->loadbalancer_unpack = nat_udp_unpack;
					session->session_free = nat_udp_free;
					 break;
			 }

			break;
		case LB_MODE_DNAT:
			session->private_interface = interface_create(protocol, saddr, sport, private_interface->ni_num);
			if(session->private_interface == NULL)
				goto error_private_interface_create;

			switch(protocol) {
				case IP_PROTOCOL_TCP:
					session->loadbalancer_pack = dnat_tcp_pack;
					session->loadbalancer_unpack = dnat_tcp_unpack;
					break;
				case IP_PROTOCOL_UDP:
					session->loadbalancer_pack = dnat_udp_pack;
					session->loadbalancer_unpack = dnat_udp_unpack;
					break;
			}

			session->session_free = dnat_free;
			break;
		case LB_MODE_DR:
			session->loadbalancer_pack = dr_pack;
			session->loadbalancer_unpack = dr_unpack;
			session->session_free = dr_free;
			break;
	}

	session->fin = false;

	Map* sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
	uint64_t key1 = (uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport;
	if(!map_put(sessions, (void*)key1, session)) {
		goto error_session_map_put1;
	}

	sessions = ni_config_get(server->server_interface->ni, PN_LB_SESSIONS);
	uint64_t key2 = (uint64_t)session->private_interface->protocol << 48 | (uint64_t)session->private_interface->addr << 16 | (uint64_t)session->private_interface->port;
	if(!map_put(sessions, (void*)key2, session)) {
		goto error_session_map_put2;
	}

	if(!map_put(server->sessions, (void*)key2, session)) {
		goto error_session_map_put3;
	}

	session->event_id = 0;
	session_recharge(session);
	
	return session;

error_session_map_put3:
	map_remove(sessions, (void*)key2);

error_session_map_put2:
	sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
	map_remove(sessions, (void*)key1);

error_session_map_put1:
	if(session->private_interface)
		interface_delete(session->private_interface);

error_private_interface_create:
error_get_private_interface:
error_get_server:
	interface_delete(session->client_interface);

error_interface_create:
	free(session);

error_allocate_session:

	return NULL;
}

Session* session_get_from_service(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport) {
	Map* sessions = ni_config_get(ni, PN_LB_SESSIONS);
	Session* session = map_get(sessions, (void*)((uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport));

	if(session != NULL)
		session_recharge(session);

	return session;
}

bool session_free(Session* session) {
	if(session->event_id != 0) {
		event_timer_remove(session->event_id);
		session->event_id = 0;
	}

	Map* sessions = ni_config_get(session->client_interface->ni, PN_LB_SESSIONS);
	if(!map_remove(sessions, (void*)((uint64_t)session->client_interface->protocol << 48 | (uint64_t)session->client_interface->addr << 16 | (uint64_t)session->client_interface->port))) {
		printf("Can'nt remove session from servers\n");
		goto error_session_free1;
	}

	Interface* private_interface = session->private_interface;
	sessions = ni_config_get(private_interface->ni, PN_LB_SESSIONS);
	uint64_t key = (uint64_t)private_interface->protocol << 48 | (uint64_t)private_interface->addr << 16 | (uint64_t)private_interface->port;
	if(!map_remove(sessions, (void*)key)) {
		printf("Can'nt remove session from private ni\n");
		goto error_session_free2;
	}

	if(!map_remove(session->server->sessions, (void*)key)) {
		printf("Can'nt remove session from servers\n");
		goto error_session_free3;
	}

	server_is_remove_grace(session->server);
	service_is_remove_grace(session->service);

	session->session_free(session);

	free(session);

	return true;

error_session_free3:
error_session_free2:
error_session_free1:
	return false;
}

Session* session_get_from_server(NetworkInterface* ni, uint8_t protocol, uint32_t daddr, uint16_t dport) {
	Map* sessions = ni_config_get(ni, PN_LB_SESSIONS);
	uint64_t key = ((uint64_t)protocol << 48 | (uint64_t)daddr << 16 | (uint64_t)dport);

	Session* session = map_get(sessions, (void*)key);

	if(session != NULL)
		session_recharge(session);

	return session;
}

bool session_set_fin(Session* session) {
	bool gc(void* context) {
		Session* session = context;
		session->event_id = 0;
		
		printf("Timeout fin\n");
		session_free(session);
		
		return false;
	}
		
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

static bool nat_tcp_pack(Session* session, Packet* packet) {
	Interface* server_interface = session->server->server_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
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
}
static bool nat_udp_pack(Session* session, Packet* packet) {
	Interface* server_interface = session->server->server_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
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

static bool nat_tcp_unpack(Session* session, Packet* packet) {
	Interface* service_interface = session->service->service_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
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
}
static bool nat_udp_unpack(Session* session, Packet* packet) {
	Interface* service_interface = session->service->service_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(service_interface->ni->mac);
	ether->dmac = endian48(arp_get_mac(session->client_interface->ni, session->client_interface->addr));
	ip->source = endian32(service_interface->addr);
	ip->destination = endian32(session->client_interface->addr);
	udp->source = endian16(service_interface->port);
	udp->destination = endian16(session->client_interface->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}

static bool nat_tcp_free(Session* session) {
	Interface* private_interface = session->private_interface;
	interface_tcp_port_free(private_interface, private_interface->port);

	return true;
}

static bool nat_udp_free(Session* session) {
	Interface* private_interface = session->private_interface;
	interface_udp_port_free(private_interface, private_interface->port);

	return true;
}

static bool dnat_tcp_pack(Session* session, Packet* packet) {
	Interface* server_interface = session->server->server_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
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
}

static bool dnat_udp_pack(Session* session, Packet* packet) {
	Interface* server_interface = session->server->server_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(server_interface->ni->mac);
	ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));

	ip->destination = endian32(server_interface->addr);
	udp->destination = endian16(server_interface->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}

static bool dnat_tcp_unpack(Session* session, Packet* packet) {
	Interface* service_interface = session->service->service_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
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
}

static bool dnat_udp_unpack(Session* session, Packet* packet) {
	Interface* service_interface = session->service->service_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(service_interface->ni->mac);
	ether->dmac = endian48(arp_get_mac(service_interface->ni, endian32(ip->destination)));
	ip->source = endian32(service_interface->addr);
	udp->source = endian16(service_interface->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}

static bool dnat_free(Session* session) {
	//do nothing
	return true;
}

static bool dr_pack(Session* session, Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);

	Interface* server_interface = session->server->server_interface;
	ether->smac = endian48(server_interface->ni->mac);
	ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));

	return true;
}

static bool dr_unpack(Session* session, Packet* packet) {
	//do nothing
	return true;
}

static bool dr_free(Session* session) {
	//do nothing
	return true;
}

