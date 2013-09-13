#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>

#include "util.h"
#include "cfg_rules.h"

struct rp_cfg_rule_s {
    rule_type            type;
    char               * name;
    char               * match;
    rp_lb_method         lb_method;
    rp_cfg_hdrs        * headers;
    rp_cfg_log         * req_log;
    rp_cfg_log         * err_log;
    rp_cfg_downstreams * downstreams;
    rp_cfg_redirects   * redirects;

    struct timeval * rd_timeout;
    struct timeval * wr_timeout;

    LIST_ENTRY(rp_cfg_rule_s) next;
};

LIST_HEAD(rp_cfg_rules_s, rp_cfg_rule_s);

rp_cfg_rules *
rp_cfg_rules_new(void) {
    rp_cfg_rules * rules;

    rules = calloc(sizeof(rp_cfg_rules), 1);
    assert(rules != NULL);

    LIST_INIT(rules);

    return rules;
}

void
rp_cfg_rules_free(rp_cfg_rules * rules) {
    rp_cfg_rule * rule;
    rp_cfg_rule * rule_save;

    if (!rules) {
        return;
    }

    LIST_FOREACH_SAFE(rule, rules, next, rule_save) {
        LIST_REMOVE(rule, rules);

        rp_cfg_rule_free(rule);
    }

    free(rules);
}

rp_cfg_rule *
rp_cfg_rule_new(const char * name) {
    rp_cfg_rule * rule_cfg;

    assert(name != NULL);

    rule_cfg       = calloc(sizeof(rp_cfg_rule), 1);
    assert(rule_cfg != NULL);

    rule_cfg->name = strdup(name);
    assert(rule_cfg->name != NULL);

    return rule_cfg;
}

void
rp_cfg_rule_free(rp_cfg_rule * rule_cfg) {
    if (rule_cfg == NULL) {
        return;
    }

    rp_cfg_log_free(rule_cfg->req_log);
    rp_cfg_log_free(rule_cfg->err_log);
    rp_cfg_hdrs_free(rule_cfg->headers);
    rp_cfg_redirect_free(rule_cfg->redirects);
    rp_cfg_downstreams_free(rule_cfg->downstreams);

    free(rule_cfg->upstream_rd_timeout);
    free(rule_cfg->upstream_wr_timeout);
    free(rule_cfg);
}

void
rp_cfg_rule_set_lb_method(rp_cfg_rule * rule_cfg, rp_lb_method method) {
    assert(rule_cfg != NULL);

    rule_cfg->lb_method = method;
}

void
rp_cfg_rule_set_hdrs(rp_cfg_rule * rule_cfg, rp_cfg_hdrs * hdrs) {
    assert(rule_cfg != NULL);
    assert(hdrs != NULL);

    if (rule_cfg->headers) {
        rp_cfg_hdrs_free(rule_cfg->headers);
    }

    rule_cfg->headers = hdrs;
}

void
rp_cfg_rule_set_err_log(rp_cfg_rule * rule_cfg, rp_cfg_log * log_cfg) {
    assert(rule_cfg != NULL);
    assert(log_cfg != NULL);

    if (rule_cfg->err_log != NULL) {
        rp_cfg_log_free(rule_cfg->err_log);
    }

    rule_cfg->err_log = log_cfg;
}

void
rp_cfg_rule_set_req_log(rp_cfg_rule * rule_cfg, rp_cfg_log * log_cfg) {
    assert(rule_cfg != NULL);
    assert(log_cfg != NULL);

    if (rule_cfg->log_cfg != NULL) {
        rp_cfg_log_free(rule_cfg->req_log);
    }

    rule_cfg->req_log = log_cfg;
}

void
rp_cfg_rule_set_downstreams(rp_cfg_rule * rule_cfg, rp_cfg_downstreams * dstreams_cfg) {
    assert(rule_cfg != NULL);
    assert(dstreams_cfg != NULL);

    if (rule_cfg->downstreams) {
        rp_cfg_downstreams_free(rule_cfg->downstreams);
    }

    rule_cfg->downstreams = dstreams_cfg;
}

void
rp_cfg_rule_set_redirects(rp_cfg_rule * rule_cfg, rp_cfg_redirects * redirects) {
    assert(rule_cfg != NULL);

    if (rule_cfg->redirects) {
        rp_cfg_redirects_free(rule_cfg->redirects);
    }

    rule_cfg->redirects = redirects;
}

void
rp_cfg_rule_set_timeouts(rp_rcfg_rule * rule_cfg, struct timeval * rd, struct timeval * wr) {
    assert(rule_cfg != NULL);

    free(rule_cfg->rd_timeout);
    free(rule_cfg->wr_timeout);

    rule_cfg->rd_timeout = NULL;
    rule_cfg->wr_timeout = NULL;

    if (rd) {
        rule_cfg->rd_timeout = calloc(sizeof(struct timeval), 1);
        assert(rule_cfg->rd_timeout != NULL);

        memcpy(rule_cfg->rd_timeout, rd, sizeof(struct timeval));
    }

    if (wr) {
        rule_cfg->wr_timeout = calloc(sizeof(struct timeval), 1);
        assert(rule_cfg->wr_timeout != NULL);

        memcpy(rule_cfg->wr_timeout, wr, sizeof(struct timeval));
    }
}

