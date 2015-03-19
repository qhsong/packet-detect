#ifndef COMMON_H
#define COMMON_H

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int32_t ihl:4,
	version:4;
#else 
	u_int32_t version:4,
	ihl:4;
#endif
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr,daddr;
};

struct app_stats {
	u_int64_t numPkts;
	u_int64_t numBytes;
	u_int64_t numStringMatches;
};
#endif
