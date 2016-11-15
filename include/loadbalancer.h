#ifndef __LOADBALANCER_H__
#define __LOADBALANCER_H__

#include <stdint.h>
#include <util/map.h>
#include <net/ni.h>
#include <stdbool.h>

int lb_ginit();
int lb_init();
void lb_loop();
bool lb_process(Packet* packet, int ni_num);
Map* lb_get_services(int ni_num);
Map* lb_get_servers(int ni_num); 
Map* lb_get_sessions(int ni_num); 

typedef struct _LoadBalancer {
	Map* services;
	Map* servers;
	Map* sessions;
} LoadBalancer;

#endif /* __LOADBALANCER_H__ */
