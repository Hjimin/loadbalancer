#include <stdio.h>
#include <string.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <util/event.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "dnat.h"
#include "service.h"
#include "session.h"
#include "util.h"

static bool dnat_free(Session* session);
static bool dnat_tcp_translate(Session* session, Packet* packet);
static bool dnat_udp_translate(Session* session, Packet* packet);
static bool dnat_tcp_untranslate(Session* session, Packet* packet);
static bool dnat_udp_untranslate(Session* session, Packet* packet);

Session* dnat_tcp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint) {
	Session* session = __malloc(sizeof(Session), server_endpoint->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->public_endpoint = service_endpoint;
	session->server_endpoint = server_endpoint;

	memcpy(&session->client_endpoint, client_endpoint, sizeof(Endpoint));
	memcpy(&session->private_endpoint, private_endpoint, sizeof(Endpoint));

	session->event_id = 0;
	if(!session_recharge(session)) {
		dnat_free(session);
		return NULL;
	}

	session->fin = false;

	session->translate = dnat_tcp_translate;
	session->untranslate = dnat_tcp_untranslate;
	session->free = dnat_free;
	session->mode = DNAT;

	return session;
}

Session* dnat_udp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint) {
	Session* session = __malloc(sizeof(Session), server_endpoint->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->public_endpoint = service_endpoint;
	session->server_endpoint = server_endpoint;

	memcpy(&session->client_endpoint, client_endpoint, sizeof(Endpoint));
	memcpy(&session->private_endpoint, client_endpoint, sizeof(Endpoint));

	session->event_id = 0;
	if(!session_recharge(session)) {
		dnat_free(session);
		return NULL;
	}

	session->fin = false;

	session->translate = dnat_udp_translate;
	session->untranslate = dnat_udp_untranslate;
	session->free = dnat_free;

	return session;
}

static bool dnat_free(Session* session) {
	__free(session, session->server_endpoint->ni->pool);

	return true;
}

static bool dnat_tcp_translate(Session* session, Packet* packet) {
	Endpoint* server_endpoint = session->server_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)((uint8_t*)ip + ip->ihl * 4);

	ether->smac = endian48(server_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(server_endpoint->ni, server_endpoint->addr, session->private_endpoint.addr));

	tcp_dest_translate(packet, server_endpoint->addr,  server_endpoint->port);
	ip->checksum = 0;
	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

	if(session->fin && tcp->ack) {
		event_timer_remove(session->event_id);
		service_free_session(session);
	} else
		if(!session_recharge(session))
			service_free_session(session);

	return true;
}

static bool dnat_udp_translate(Session* session, Packet* packet) {
	Endpoint* server_endpoint = session->server_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(server_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(server_endpoint->ni, session->private_endpoint.addr, server_endpoint->addr));

	ip->destination = endian32(server_endpoint->addr);
	udp->destination = endian16(server_endpoint->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	if(!session_recharge(session))
		service_free_session(session);

	return true;
}

static bool dnat_tcp_untranslate(Session* session, Packet* packet) {
	Endpoint* public_endpoint = session->public_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)((uint8_t*)ip + ip->ihl * 4);

	ether->smac = endian48(public_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(public_endpoint->ni, session->client_endpoint.addr, public_endpoint->addr));
	tcp_src_translate(packet, public_endpoint->addr, public_endpoint->port);
	ip->checksum = 0;
	ip->checksum = endian16(checksum(ip, ip->ihl * 4));

	if(tcp->fin) {
		if(!session_set_fin(session))
			service_free_session(session);
	} else {
		if(!session_recharge(session))
			service_free_session(session);
	}

	return true;
}

static bool dnat_udp_untranslate(Session* session, Packet* packet) {
	Endpoint* public_endpoint = session->public_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(public_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(public_endpoint->ni, public_endpoint->addr, session->client_endpoint.addr));
	ip->source = endian32(public_endpoint->addr);
	udp->source = endian16(public_endpoint->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	if(!session_recharge(session))
		service_free_session(session);

	return true;
}
