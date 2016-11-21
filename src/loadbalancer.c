#include <stdio.h>
#include <_malloc.h>
#include <util/list.h>
#include <util/map.h>
#include <util/types.h>
#include <util/event.h>
#include <net/nic.h>
#include <net/ether.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/arp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/dhcp.h>

#include "loadbalancer.h"
#include "service.h"
#include "server.h"
#include "session.h"

extern void* __gmalloc_pool;
static LoadBalancer** loadbalancers;

int lb_ginit() {
	uint32_t count = nic_count();
	if(count < 2)
		return -1;

	loadbalancers = (LoadBalancer**)__malloc(sizeof(LoadBalancer*) * count, __gmalloc_pool);

	for(int i = 0; i < count; i++) {
		NIC* nic = nic_get(i);
		loadbalancers[i] = (LoadBalancer*)__malloc(sizeof(LoadBalancer), nic->pool);
		loadbalancers[i]->services = map_create(16, NULL, NULL, nic->pool);
		loadbalancers[i]->servers = map_create(16, NULL, NULL, nic->pool);
		loadbalancers[i]->sessions = map_create(1024, NULL, NULL, nic->pool);
	}   


	return 0;
}

void lb_destroy() {
}

Map* lb_get_services(int ni_num) {
	    return loadbalancers[ni_num]->services;
}

Map* lb_get_servers(int ni_num) {
	    return loadbalancers[ni_num]->servers;
}

Map* lb_get_sessions(int ni_num) {
	    return loadbalancers[ni_num]->sessions;
}

int lb_init() {
	event_init();
	return 0;
}

void lb_loop() {
	event_loop();
}

bool lb_process(Packet* packet, int ni_num) {
	if(arp_process(packet))
		return true;

	if(icmp_process(packet))
		return true;

	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;
		Endpoint destination_endpoint;
		Endpoint source_endpoint;

		destination_endpoint.ni = packet->nic;
		destination_endpoint.ni_num = ni_num;
		source_endpoint.ni = packet->nic;
		source_endpoint.ni_num = ni_num;

		source_endpoint.addr = endian32(ip->source);
		destination_endpoint.addr = endian32(ip->destination);
		source_endpoint.protocol = ip->protocol;
		destination_endpoint.protocol = ip->protocol;

		switch(ip->protocol) {
			case IP_PROTOCOL_TCP:
				;
				TCP* tcp = (TCP*)((uint8_t*)ip + ip->ihl * 4);
				source_endpoint.port = endian16(tcp->source);
				destination_endpoint.port = endian16(tcp->destination);
				break;
			case IP_PROTOCOL_UDP:
				;
				UDP* udp = (UDP*)ip->body;
				if(udp->source == endian16(DHCP_SERVER_PORT)) {
					dhcp_process(packet);
					return true;
				}

				source_endpoint.port = endian16(udp->source);
				destination_endpoint.port = endian16(udp->destination);
				break;
			default:
				return false;
		}

		//Service
		Session* session = service_get_session(&source_endpoint);
		if(!session) {
			session = service_alloc_session(&destination_endpoint, &source_endpoint);
		}

		if(session) {
			NIC* server_ni = session->server_endpoint->ni;
			session->translate(session, packet);
			nic_output(server_ni, packet);
			return true;
		}

		//Server
		session = server_get_session(&destination_endpoint);
		if(session) {
			NIC* _ni = session->public_endpoint->ni;
			session->untranslate(session, packet);
			nic_output(_ni, packet);
			return true;
		}

		return false;
	}
	return false;
}

bool lb_is_all_destroied() {
	int count = nic_count();
	for(int i = 0; i < count; i++) {
//		NIC* ni = nic_get(i);
//		Map* services = nic_config_get(ni, SERVICES);
		Map* services = lb_get_services(i);
		if(services && !map_is_empty(services))
			return false;

//		Map* servers = nic_config_get(ni, SERVERS);
		Map* servers = lb_get_servers(i);
		if(servers && !map_is_empty(servers))
			return false;
	}

	return true;
}

void lb_remove(uint64_t wait) {
	int count = nic_count();
	for(int i = 0; i < count; i++) {
//		NIC* ni = nic_get(i);
//		Map* services = nic_config_get(ni, SERVICES);
		Map* services = lb_get_services(i);
		if(services && !map_is_empty(services)) {
			MapIterator iter;
			map_iterator_init(&iter, services);
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_next(&iter);
				Service* service = entry->data;
				service_remove(service, wait);
			}
		}

//		Map* servers = nic_config_get(ni, SERVERS);
		Map* servers = lb_get_servers(i);
		if(servers && !map_is_empty(servers)) {
			MapIterator iter;
			map_iterator_init(&iter, servers);
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_next(&iter);
				Server* server = entry->data;
				server_remove(server, wait);
			}
		}
	}
}

void lb_remove_force() {
	int count = nic_count();
	for(int i = 0; i < count; i++) {
//		NIC* ni = nic_get(i);
//		Map* services = nic_config_get(ni, SERVICES);
		Map* services = lb_get_services(i);
		if(services && !map_is_empty(services)) {
			MapIterator iter;
			map_iterator_init(&iter, services);
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_next(&iter);
				Service* service = entry->data;
				service_remove_force(service);
			}
		}

//		Map* servers = nic_config_get(ni, SERVERS);
		Map* servers = lb_get_servers(i);
		if(servers && !map_is_empty(servers)) {
			MapIterator iter;
			map_iterator_init(&iter, servers);
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_next(&iter);
				Server* server = entry->data;
				server_remove_force(server);
			}
		}
	}
}
