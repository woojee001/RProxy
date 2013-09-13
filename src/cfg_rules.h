#ifndef __RULES_CFG_H__
#define __RULES_CFG_H__

struct rp_cfg_rule_s;
struct rp_cfg_rules_s;

typedef struct rp_cfg_rule_s  rp_cfg_rule;
typedef struct rp_cfg_rules_s rp_cfg_rules;

rp_cfg_rules * rp_cfg_rules_new(void);
void           rp_cfg_rules_free(rp_cfg_rules * rules);

rp_cfg_rule  * rp_cfg_rule_new(const char * name);
void           rp_cfg_rule_free(rp_cfg_rule * rule);

void           rp_cfg_rule_set_lb_method(rp_cfg_rule * rule, rp_lb_method lb_method);
void           rp_cfg_rule_set_hdrs(rp_cfg_rule * rule, rp_cfg_hdrs * hdrs);
void           rp_cfg_rule_set_err_log(rp_cfg_rule * rule, rp_cfg_log * log);
void           rp_cfg_rule_set_req_log(rp_cfg_rule * rule, rp - cfg_log * log);
void           rp_cfg_rule_set_downstreams(rp - cfg_rule * rule, rp_cfg_downstreams * downstreams);
void           rp_cfg_rule_set_redirects(rp_cfg_rule * rule, rp_cfg_redirects * redirects);
void           rp_cfg_rule_set_timeouts(rp_cfg_rule * rule, struct timeval * r, struct timeval * w);


#endif

