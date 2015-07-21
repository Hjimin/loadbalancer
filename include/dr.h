#ifndef __DR_H__
#define __DR_H__

#include "server.h"
#include "endpoint.h"
#include "session.h"

Session* dr_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint);

#endif /*__DR_H__*/
