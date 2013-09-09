#ifndef __RP_CFG_H__
#define __RP_CFG_H__

struct rp_cfg_log_s;
struct rp_cfg_rule_s;
struct rp_cfg_x509_ext_s;
struct rp_cfg_ssl_crl_s;
struct rp_cfg_headers_s;
struct rp_cfg_downstream_s;
struct rp_cfg_vhost_s;
struct rp_cfg_server_s;
struct rp_cfg_rusage_s;
struct rp_cfg_s;

typedef struct rp_cfg_log_s        rp_cfg_log;
typedef struct rp_cfg_rule_s       rp_cfg_rule;
typedef struct rp_cfg_x509_ext_s   rp_cfg_x509_ext;
typedef struct rp_cfg_ssl_crl_s    rp_cfg_ssl_crl;
typedef struct rp_cfg_headers_s    rp_cfg_headers;
typedef struct rp_cfg_downstream_s rp_cfg_downstream;
typedef struct rp_cfg_vhost_s      rp_cfg_vhost;
typedef struct rp_cfg_server_s     rp_cfg_server;
typedef struct rp_cfg_rusage_s     rp_cfg_rusage;
typedef struct rp_cfg_s            rp_cfg;
typedef struct evhtp_ssl_cfg_s     rp_cfg_ssl;

void rp_cfg_set_user(rp_cfg * cfg, const char * user);
void rp_cfg_set_group(rp_cfg * cfg, const char * group);
void rp_cfg_set_rootdir(rp_cfg * cfg, const char * rootdir);
void rp_cfg_set_max_nofile(rp_cfg * cfg, const int nofile);
void rp_cfg_set_daemonize(rp_cfg * cfg, const bool daemonize);


#endif

