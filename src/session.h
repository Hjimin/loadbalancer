#include <net/ni.h>

#include "service.h"
#include "server.h"

typedef struct {
	uint8_t		protocol;
	uint32_t	s_addr;
	uint16_t	s_port;
	uint32_t	v_addr;
	uint32_t	v_port;
	Service*	service;
	Server*		server;
	uint64_t	event_id;
	bool		fin;
} Session;

Session* session_alloc(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
Session* session_get(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
bool session_free(Session* session);
Session* session_get_nat(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
Session* session_get_dnat(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
bool session_set_fin(Session* session);
