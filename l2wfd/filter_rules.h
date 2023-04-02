#ifndef _FILTER_RULES_H_
#define _FILTER_RULES_H_

// comments this define it will completely turns off FILTER feature
#define USE_PACKET_FILTER


#ifdef USE_PACKET_FILTER

#include <stdint.h>
#include <rte_ethdev.h>

void filter_set(const char *rules, uint16_t rules_size);
void filter_store_callback(uint16_t portid, const struct rte_eth_rxtx_callback *cb);
void filter_remove_callback(void);

uint16_t filter_pckts_cb(uint16_t port, uint16_t qidx, struct rte_mbuf *pkts[],
						 uint16_t nb_pkts, uint16_t max_pkts, void *user_param);


int filter_srv_run(int port);
void filter_srv_stop(void);

#endif /* USE_PACKET_FILTER */



#endif /* _FILTER_RULES_H_ */
