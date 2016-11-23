#include <stdio.h>
#include <string.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <util/map.h>
#include <util/event.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "nat.h"
#include "endpoint.h"
#include "session.h"
#include "service.h"
#include "util.h"

static bool nat_tcp_translate(Session* session, Packet* packet);
static bool nat_udp_translate(Session* session, Packet* packet);
static bool nat_tcp_untranslate(Session* session, Packet* packet);
static bool nat_udp_untranslate(Session* session, Packet* packet);
static bool nat_tcp_free(Session* session);
static bool nat_udp_free(Session* session);

Session* nat_tcp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint) {
	Session* session = __malloc(sizeof(Session), server_endpoint->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->server_endpoint = server_endpoint;
	session->public_endpoint = service_endpoint;

	memcpy(&session->client_endpoint, client_endpoint, sizeof(Endpoint));
	memcpy(&session->private_endpoint, private_endpoint, sizeof(Endpoint));
	session->private_endpoint.port = tcp_port_alloc(private_endpoint->ni, private_endpoint->addr);
	if(!session->private_endpoint.port) {
		__free(session, server_endpoint->ni->pool);
	}

	session->event_id = 0;
	if(!session_recharge(session)) {
		nat_tcp_free(session);
		return NULL;
	}
	session->fin = false;

	session->translate = nat_tcp_translate;
	session->untranslate = nat_tcp_untranslate;
	session->free = nat_tcp_free;
	session->mode = NAT;

	return session;
}

Session* nat_udp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint) {
	Session* session = __malloc(sizeof(Session), server_endpoint->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->server_endpoint = server_endpoint;
	session->public_endpoint = service_endpoint;

	memcpy(&session->client_endpoint, client_endpoint, sizeof(Endpoint));
	memcpy(&session->private_endpoint, private_endpoint, sizeof(Endpoint));
	session->private_endpoint.port = udp_port_alloc(private_endpoint->ni, private_endpoint->addr);
	if(!session->private_endpoint.port) {
		__free(session, server_endpoint->ni->pool);
	}

	session->event_id = 0;
	if(!session_recharge(session)) {
		nat_udp_free(session);
		return NULL;
	}
	session->fin = false;

	session->translate = nat_udp_translate;
	session->untranslate = nat_udp_untranslate;
	session->free = nat_udp_free;

	return session;
}

static bool nat_tcp_free(Session* session) {
	tcp_port_free(session->server_endpoint->ni, session->private_endpoint.addr, session->private_endpoint.port);
	__free(session, session->server_endpoint->ni->pool);

	return true;
}

static bool nat_udp_free(Session* session) {
	udp_port_free(session->server_endpoint->ni, session->private_endpoint.addr, session->private_endpoint.port);
	__free(session, session->server_endpoint->ni->pool);

	return true;
}

static bool nat_tcp_translate(Session* session, Packet* packet) {
	Endpoint* server_endpoint = session->server_endpoint;
	Endpoint* private_endpoint = &(session->private_endpoint);
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	ether->smac = endian48(session->server_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(session->server_endpoint->ni, server_endpoint->addr, private_endpoint->addr));

	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)((uint8_t*)ip + ip->ihl * 4);
	tcp_src_translate(packet, private_endpoint->addr, private_endpoint->port);
	tcp_dest_translate(packet, server_endpoint->addr, server_endpoint->port);
	ip->checksum = 0;
	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

	if(session->fin && tcp->ack) {
		event_timer_remove(session->event_id);
		service_free_session(session);
	} else {
		if(!session_recharge(session))
			service_free_session(session);
	}

	return true;
}

static bool nat_udp_translate(Session* session, Packet* packet) {
	Endpoint* server_endpoint = session->server_endpoint;
	Endpoint* private_endpoint = &(session->private_endpoint);
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(session->server_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(session->server_endpoint->ni, server_endpoint->addr, private_endpoint->addr));
	ip->source = endian32(private_endpoint->addr);
	ip->destination = endian32(server_endpoint->addr);
	udp->source = endian16(private_endpoint->port);
	udp->destination = endian16(server_endpoint->port);
	ip->checksum = 0;
	ip->checksum = endian16(checksum(ip, ip->ihl * 4));
// 	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	if(!session_recharge(session))
		service_free_session(session);

	return true;
}

static bool nat_tcp_untranslate(Session* session, Packet* packet) {
	Endpoint* public_endpoint = session->public_endpoint;
	Endpoint* client_endpoint = &session->client_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)((uint8_t*)ip + ip->ihl * 4);

	ether->smac = endian48(session->public_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(session->public_endpoint->ni, session->client_endpoint.addr, session->public_endpoint->addr));

	tcp_src_translate(packet, public_endpoint->addr, public_endpoint->port);
	tcp_dest_translate(packet, client_endpoint->addr, client_endpoint->port);
	ip->checksum = 0;
	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

	if(tcp->fin) {
		if(!session_set_fin(session)) {
			service_free_session(session);
		}
	} else {
		if(!session_recharge(session)) {
			service_free_session(session);
		}
	}

	return true;
}

static bool nat_udp_untranslate(Session* session, Packet* packet) {
	Endpoint* public_endpoint = session->public_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(session->public_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(session->public_endpoint->ni, session->client_endpoint.addr, session->public_endpoint->addr));
	ip->source = endian32(public_endpoint->addr);
	ip->destination = endian32(session->client_endpoint.addr);
	udp->source = endian16(public_endpoint->port);
	udp->destination = endian16(session->client_endpoint.port);
	ip->checksum = 0;
	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

// 	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	if(!session_recharge(session)) {
		service_free_session(session);
	} 
	return true;
}
