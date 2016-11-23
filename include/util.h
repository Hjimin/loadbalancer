#include <net/tcp.h>
#include <net/checksum.h>

inline void tcp_src_translate(Packet* packet, uint32_t new_ip, uint16_t new_port) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)((uint8_t*)ip + ip->ihl * 4);

	uint32_t sum = (uint16_t)~tcp->checksum;
	int16_t* carry = (int16_t*)&sum + 1;

	if(new_ip != endian32(ip->source)) {
		sum -= (uint16_t)(ip->source & 0xffff);
		sum -= (uint16_t)(ip->source >> 16);

		ip->source = endian32(new_ip);
		sum += (uint16_t)(ip->source & 0xffff);
		sum += (uint16_t)(ip->source >> 16);
	}

	if(new_port != endian16(tcp->source)) {
		sum -= tcp->source;

		tcp->source = endian16(new_port);
		sum += tcp->source;
	}

	while(*carry) { 
		sum = (sum & 0xffff) + *carry;
	}


	tcp->checksum = (uint16_t)~sum;
}

inline void tcp_dest_translate(Packet* packet, uint32_t new_ip, uint16_t new_port) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)((uint8_t*)ip + ip->ihl * 4);

	uint32_t sum = (uint16_t)~tcp->checksum;
	int16_t* carry = (int16_t*)&sum + 1;

	if(new_ip != endian32(ip->destination)) {
		sum -= (uint16_t)(ip->destination & 0xffff);
		sum -= (uint16_t)(ip->destination >> 16);

		ip->destination = endian32(new_ip);
		sum += (uint16_t)(ip->destination & 0xffff);
		sum += (uint16_t)(ip->destination >> 16);
	}

	if(new_port != endian16(tcp->destination)) {
		sum -= tcp->destination;

		tcp->destination = endian16(new_port);
		sum += tcp->destination;
	}

	while(*carry) { 
		sum = (sum & 0xffff) + *carry;
	}

	tcp->checksum = (uint16_t)~sum;
}

inline void udp_src_port_translate(TCP* udp, uint16_t old_port, uint16_t new_port) {
	uint32_t sum = ~endian16(udp->checksum);
	int16_t* carry = (int16_t*)&sum + 1;
	sum -= old_port;
	sum += *carry;
	sum += new_port;
	sum += *carry;

	udp->checksum = endian16((uint16_t)~sum);
	udp->source = new_port;
}

inline void udp_dest_port_translate(TCP* udp, uint16_t old_port, uint16_t new_port) {
	uint32_t sum = ~endian16(udp->checksum);
	int16_t* carry = (int16_t*)&sum + 1;
	sum -= old_port;
	sum += *carry;
	sum += new_port;
	sum += *carry;

	udp->checksum = endian16((uint16_t)~sum);
	udp->destination = new_port;
}
