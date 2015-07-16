#ifndef __LOADBALANCER_H__
#define __LOADBALANCER_H__

#include <stdint.h>
#include <util/map.h>
#include <net/ni.h>
#include <stdbool.h>

int lb_ginit();
int lb_init();
void lb_loop();
bool lb_process(Packet* packet);

#endif /* __LOADBALANCER_H__ */
