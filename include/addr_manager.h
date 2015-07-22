#ifndef __PRIVATE_H__
#define __PRIVATE_H__

#include <net/ni.h>
#define ADDRS		"net.lb.addrs" 

bool addr_alloc(NetworkInterface* ni, uint32_t addr);
bool addr_free(NetworkInterface* ni, uint32_t addr);

#endif /*__PRIVATE_H__*/
