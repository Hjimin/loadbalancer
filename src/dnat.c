#include <stdio.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "dnat.h"
#include "service.h"
#include "server.h"
#include "session.h"

static bool dnat_free(Session* session);
static bool dnat_tcp_translate(Session* session, Packet* translateet);
static bool dnat_udp_translate(Session* session, Packet* translateet);
static bool dnat_tcp_untranslate(Session* session, Packet* translateet);
static bool dnat_udp_untranslate(Session* session, Packet* translateet);

Session* dnat_tcp_session_alloc(Endpoint* service_endpoint, Endpoint* server_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr) {
	Session* session = __malloc(sizeof(Session), server_endpoint->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->service_endpoint = service_endpoint;
	session->server_endpoint = server_endpoint;

	session->public_endpoint.protocol = IP_PROTOCOL_TCP;
	session->public_endpoint.addr = public_addr;
	session->public_endpoint.port = public_port;

	session->private_endpoint.protocol = IP_PROTOCOL_TCP;
	session->private_endpoint.addr = public_addr;
	session->private_endpoint.port = public_port;;

	session->event_id = 0;
	session->fin = false;
	session->translate = dnat_tcp_translate;
	session->untranslate = dnat_tcp_untranslate;
	session->free = dnat_free;

	return session;
}

Session* dnat_udp_session_alloc(Endpoint* service_endpoint, Endpoint* server_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr) {
	Session* session = __malloc(sizeof(Session), server_endpoint->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->service_endpoint = service_endpoint;
	session->server_endpoint = server_endpoint;

	session->public_endpoint.protocol = IP_PROTOCOL_UDP;
	session->public_endpoint.addr = public_addr;
	session->public_endpoint.port = public_port;

	session->private_endpoint.protocol = IP_PROTOCOL_UDP;
	session->private_endpoint.addr = public_addr;
	session->private_endpoint.port = public_port;;

	session->event_id = 0;
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

static bool dnat_tcp_translate(Session* session, Packet* translateet) {
	Endpoint* server_endpoint = session->server_endpoint;
	Ether* ether = (Ether*)(translateet->buffer + translateet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	ether->smac = endian48(server_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(server_endpoint->ni, session->public_endpoint.addr, server_endpoint->addr));

	ip->destination = endian32(server_endpoint->addr);
	tcp->destination = endian16(server_endpoint->port);

	tcp_pack(translateet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
	if(session->fin && tcp->ack)
		service_free_session(session);

	return true;
}

static bool dnat_udp_translate(Session* session, Packet* translateet) {
	Endpoint* server_endpoint = session->server_endpoint;
	Ether* ether = (Ether*)(translateet->buffer + translateet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(server_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(server_endpoint->ni, session->public_endpoint.addr, server_endpoint->addr));

	ip->destination = endian32(server_endpoint->addr);
	udp->destination = endian16(server_endpoint->port);

	udp_pack(translateet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}

static bool dnat_tcp_untranslate(Session* session, Packet* translateet) {
	Endpoint* service_endpoint = session->service_endpoint;
	Ether* ether = (Ether*)(translateet->buffer + translateet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	ether->smac = endian48(service_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(service_endpoint->ni, endian32(ip->destination), session->public_endpoint.addr));
	ip->source = endian32(service_endpoint->addr);
	tcp->source = endian16(service_endpoint->port);
		
	if(tcp->fin) {
		session_set_fin(session);
	}

	tcp_pack(translateet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);

	return true;
}

static bool dnat_udp_untranslate(Session* session, Packet* translateet) {
	Endpoint* service_endpoint = session->service_endpoint;
	Ether* ether = (Ether*)(translateet->buffer + translateet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(service_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(service_endpoint->ni, endian32(ip->destination), session->public_endpoint.addr));
	ip->source = endian32(service_endpoint->addr);
	udp->source = endian16(service_endpoint->port);

	udp_pack(translateet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}
