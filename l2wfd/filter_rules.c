#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_rwlock.h>
#include <rte_spinlock.h>

#include <jansson.h>

#include "filter_rules.h"


#ifdef USE_PACKET_FILTER

typedef struct filter_rule {
	char *action;
	char *field;
	char *value;
	struct rte_ether_addr mac_addr;
	rte_be32_t ipv4;
} filter_rule_t;

//
static filter_rule_t **filter_rules = NULL;

static const struct rte_eth_rxtx_callback *filter_cb[RTE_MAX_ETHPORTS] = {0};

static rte_spinlock_t lock;

/**
 * @brief free filter rules
 * @param rules - array of rules
 */
static void free_filter_rules(filter_rule_t **rules)
{
	if (!rules)	return;

	for (int i = 0; rules[i] != NULL; i++)
	{
		filter_rule_t *rule = rules[i];
		free(rule->action);
		free(rule->field);
		free(rule->value);
	}

	free(*rules);
	free(rules);
}

/**
 * @brief Set new the filter rules pointer
 * Set new list of rules to replace the currently active ones and free the memory of the old rules.
 * @param old - current rules
 * @param new - new rules
 */
static void set_new_rules(filter_rule_t ***old, filter_rule_t ***new)
{
	filter_rule_t **tmp = *old;

	rte_spinlock_lock(&lock);
	*old = *new;
	rte_spinlock_unlock(&lock);

	free_filter_rules(tmp);
}

/**
 * @brief some processing incoming rules (for futher performance)
 * @param rules - array of rules
 */
static void prepare_filter_actions(filter_rule_t **rules)
{
	for (int i = 0; rules[i] != NULL; i++)
	{
		filter_rule_t *rule = rules[i];

		if (strstr(rule->field, "ip_dst"))
		{
			struct in_addr inp;
			int ret = inet_aton(rule->value, &inp);
			if (ret == 0)
			{
				rule->ipv4 = 0;
				RTE_LOG(ERR, USER1, "Invalid ip address was specified - '%s'", rule->value);
			}
			else
			{
				rule->ipv4 = (rte_be32_t)inp.s_addr;
			}
		}
		else if (strstr(rule->field, "mac_src"))
		{
			int ret = rte_ether_unformat_addr(rule->value, &rule->mac_addr);
			if (ret < 0)
			{
				memset(&rule->mac_addr, 0, sizeof(struct rte_ether_addr));
				RTE_LOG(ERR, USER1, "Invalid mac address was specified - '%s'", rule->value);
			}
		}
	}
}

/**
 * @brief helper to clone json string
 * @param dst - new target allocated space
 * @param jval - string in json format
 */
static void set_json_string(char **dst, const json_t *jval)
{
	const char *str = json_string_value(jval);
	if (!str) return;
	size_t ln = strlen(str);
	*dst = calloc(1, ln+1);
	strncpy(*dst, str, ln);
}

/**
 * @brief setup new commands sequence for package filtering
 * @param json_arrays - command's array in json format
 * @return
 * - 0 - success
 * - 1 - error
 */
static int set_filter_rules(const json_t *json_arrays)
{
	uint16_t num = json_array_size(json_arrays);
	if (num == 0)
	{
		RTE_LOG(ERR, USER1, "filter: incorrect command's array\n");
		return 1;
	}

	// 1.
	size_t sz = sizeof(filter_rule_t**) * (num + 1);
	filter_rule_t **new_rules = (filter_rule_t **)calloc(1, sz);
	if (!new_rules)
	{
		RTE_LOG(CRIT, MALLOC, "filter: memory allocation error for %ld bytes\n", sz);
		return 1;
	}

	// 2.
	sz = sizeof(filter_rule_t) * num;
	filter_rule_t *rules = (filter_rule_t *)calloc(1, sz);
	if (!rules)
	{
		RTE_LOG(CRIT, MALLOC, "filter: memory allocation error for %ld bytes\n", sz);
		return 1;
	}

	// 3.
	for(int i = 0; i < num; i++)
	{
		new_rules[i] = rules+i;
	}

	// 4.
	size_t index;
	json_t *obj;
	json_t *jval;

	json_array_foreach(json_arrays, index, obj)
	{
		if (!json_is_object(obj))
			continue;

		filter_rule_t *rule = new_rules[index];

		jval = json_object_get(obj, "action");
		set_json_string(&rule->action, jval);

		jval = json_object_get(obj, "field");
		set_json_string(&rule->field, jval);

		jval = json_object_get(obj, "value");
		set_json_string(&rule->value, jval);
	}

	prepare_filter_actions(new_rules);

	set_new_rules(&filter_rules, &new_rules);
	return 0;
}

/**
 * @brief helper function (for test task)
 */
void filter_set(const char *rules, uint16_t rules_size)
{
	/*
	const char *rules =
			"[ {"
			"	\"action\": \"drop\","
			"	\"field\": \"mac_src\","
			"	\"value\": \"00:11:22:33:44:55:66\""
			"},"
			"{"
			"	\"action\": \"drop\","
			"	\"field\": \"ip_dst\","
			"	\"value\": \"192.168.0.1\""
			"} ]";
	*/

	//[{"action": "drop","field": "mac_src","value": "11:22:33:44:55:66"},{"action": "drop","field": "ip_dst","value": "192.168.0.1"}]

	RTE_LOG(INFO, USER1, "filter: rules: %s \n", rules);

	json_error_t error;
	json_t *jdata = json_loadb(rules, rules_size, JSON_DECODE_ANY, &error);
	if (!jdata)
	{
		RTE_LOG(ERR, USER1, "jsonb: can't load data %s\n%s\n", error.text, error.source);
		return;
	}

	rte_spinlock_init(&lock);

	set_filter_rules(jdata);
	json_decref(jdata);
}

/**
 * @brief To store callback pointer
 * @param portid - port index
 * @param cb - RX/TX callback function
 */
void filter_store_callback(uint16_t portid, const struct rte_eth_rxtx_callback *cb)
{
	filter_cb[portid] = cb;
}

/**
 * @brief To remove stored callbacks
 */
void filter_remove_callback(void)
{
	uint16_t portid;
	RTE_ETH_FOREACH_DEV(portid) {
	   rte_eth_remove_rx_callback(portid, 0, filter_cb[portid]);
	}

	free_filter_rules(filter_rules);
}

/**
 * @brief The packet filtering callback
 * @param port - unused
 * @param qidx - unused
 * @param pkts - packets for filtering
 * @param nb_pkts - number of packets
 * @param max_pkts - unused
 * @param params - unused
 * @return The number of packets returned
 */
uint16_t filter_pckts_cb(uint16_t port, uint16_t qidx, struct rte_mbuf *pkts[],
				uint16_t nb_pkts, uint16_t max_pkts, void *params)
{
	(void) port;
	(void) qidx;
	(void) max_pkts;
	(void) params;

	struct rte_mbuf *mbuf;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;

	rte_spinlock_lock(&lock);

	filter_rule_t **rules = filter_rules;

	for (int i = 0; rules[i] != NULL; i++)
	{
		filter_rule_t *rule = rules[i];

		if (strstr(rule->action, "drop"))
		{
			for (uint16_t i = 0; i < nb_pkts; i++)
			{
				mbuf = pkts[i];
				eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

				if (strstr(rule->field, "ip_dst"))
				{
					if (RTE_ETH_IS_IPV4_HDR(mbuf->packet_type))
					{
						ipv4_hdr = (struct rte_ipv4_hdr *) (eth_hdr + 1);
						if (ipv4_hdr->dst_addr == rule->ipv4)
						{
							rte_pktmbuf_free_bulk(pkts, nb_pkts);
							nb_pkts = 0;
						}
					}
				}
				else if (strstr(rule->field, "mac_src"))
				{
					if (rte_is_same_ether_addr(&rule->mac_addr, &eth_hdr->dst_addr))
					{
						rte_pktmbuf_free_bulk(pkts, nb_pkts);
						nb_pkts = 0;
					}
				}
			}
		}
	}

	rte_spinlock_unlock(&lock);
	return nb_pkts;
}

#endif /* USE_PACKET_FILTER */
