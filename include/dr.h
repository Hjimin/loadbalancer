#ifndef __DR_H__
#define __DR_H__

#include "server.h"
#include "endpoint.h"
#include "session.h"

Session* dr_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr);

#endif /*__DR_H__*/
