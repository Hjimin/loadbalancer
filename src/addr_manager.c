#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <net/ni.h>
#include <util/map.h>

#include "addr_manager.h"

bool addr_alloc(NetworkInterface* ni, uint32_t addr) {
	Map* addrs = ni_config_get(ni, ADDRS);
	if(!addrs) {
		addrs = map_create(16, NULL, NULL, ni->pool);
		if(!addrs)
			return false;

		if(!ni_config_put(ni, ADDRS, addrs)) {
			map_destroy(addrs);
			return false;
		}
	}

	uint64_t count = (uint64_t)map_get(addrs, (void*)(uintptr_t)addr);

	if(!count) {
		if(!ni_ip_add(ni, addr)) {
			printf("Can'nt allocate address\n");
			return false;
		}
	}

	count++;

	return map_update(addrs, (void*)(uintptr_t)addr, (void*)(uintptr_t)count);
}

bool addr_free(NetworkInterface* ni, uint32_t addr) {
	Map* addrs = ni_config_get(ni, ADDRS);
	if(!addrs)
		return false;

	uint64_t count = (uint64_t)map_get(addrs, (void*)(uintptr_t)addr);
	count--;

	if(!count) {
		ni_ip_remove(ni, addr);
		map_remove(addrs, (void*)(uintptr_t)addr);
		if(map_is_empty(addrs)) {
			map_destroy(addrs);
			ni_config_remove(ni, ADDRS);
		}
	} else
		return map_update(addrs, (void*)(uintptr_t)addr, (void*)(uintptr_t)count);

	return true;
}
