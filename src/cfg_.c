#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <evhtp.h>

#include "lzq.h"
#include "lzlog.h"
#include "rproxy.h"
#include "cfg_.h"

#define _FAIL                    do { \
        perror(__PRETTY_FUNCTION__);  \
        exit(EXIT_FAILURE);           \
} while (0)

#define _ADDR_K                  "addr"
#define _PORT_K                  "port"
#define _THREADS_K               "threads"
#define _BACKLOG_K               "backlog"
#define _MAX_PENDING_K           "max-pending"
#define _READ_TIMEOUT_K          "read-timeout"
#define _WRITE_TIMEOUT_K         "write-timeout"
#define _PENDING_TIMEOUT_K       "pending-timeout"
#define _HIGH_WM_K               "high-watermark"
#define _DISABLE_CLIENT_NAGLE_K  "disable-client-nagle"
#define _DISABLE_SERVER_NAGLE_K  "disable-server-nagle"
#define _DISABLE_DOWNSTR_NAGLE_K "disable-downstream-nagle"
#define _LOG_K                   "logging"
#define _REQUEST_LOG_K           "request"
#define _ERROR_LOG_K             "error"
#define _DOWNSTREAM_K            "downstream"
#define _VHOST_K                 "vhost"
#define _USER_K                  "user"
#define _GROUP_K                 "group"
#define _ROOTDIR_K               "rootdir"
#define _MAX_NOFILE_K            "max-nofile"
#define _DAEMONIZE_K             "damonize"
#define _SERVER_K                "server"
#define _ENABLED_K               "enabled"
#define _SSL_K                   "ssl"
#define _SSL_CERT_K              "cert"
#define _SSL_KEY_K               "key"
#define _SSL_CA_K                "ca"
#define _SSL_CAPATH_K            "capath"
#define _SSL_CIPHERS_K           "ciphers"
#define _SSL_VERIFY_PEER_K       "verify-peer"
#define _SSL_ENFORCE_PEER_CERT_K "enforce-peer-cert"
#define _SSL_VERIFY_DEPTH_K      "verify-depth"
#define _SSL_CACHE_ENABLED_K     "cache-enabled"
#define _SSL_CACHE_SIZE_K        "cache-size"
#define _SSL_CACHE_TIMEOUT_K     "cache-timeout"
#define _SSL_PROTO_ON_K          "protocols-on"
#define _SSL_PROTO_OFF_K         "protocols-off"
#define _SSL_CTX_TIMEOUT_K       "context-timeout"
#define _SSL_CRL_K               "crl"
#define _RETRY_K                 "retry"
#define _N_CONNS_K               "connections"
#define _RULE_K                  "rule"
#define _STRIP_HDRS_K            "strip-headers"
#define _ALIASES_K               "aliases"
#define _HEADERS_K               "headers"


#define _GEN_STR_SET_FUNCTION(_cfg_type, _name, _member)                                        \
    void rp_cfg_ ## _cfg_type ## _set_ ## _name(rp_cfg_ ## _cfg_type * cfg, const char * val) { \
        assert(cfg != NULL);                                                                    \
                                                                                                \
        free(cfg->_member); cfg->_member = NULL;                                                \
                                                                                                \
        if (val != NULL) {                                                                      \
            cfg->_member = strdup(val);                                                         \
        }                                                                                       \
    }

#define _GEN_SET_FUNCTION(_cfg_type, _name, _member, _vtype)                              \
    void rp_cfg_ ## _cfg_type ## _set_ ## _name(rp_cfg_ ## _cfg_type * cfg, _vtype val) { \
        assert(cfg != NULL);                                                              \
                                                                                          \
        cfg->_member = val;                                                               \
    }

#define _GEN_GET_FUNCTION(_cfg_type, _name, _member, _vtype)                    \
    _vtype rp_cfg_ ## _cfg_type ## _get_ ## _name(rp_cfg_ ## _cfg_type * cfg) { \
        assert(cfg != NULL);                                                    \
        return cfg->_member;                                                    \
    }

#define _GEN_FUNCTIONS(_cfg_type, _name, _member, _vtype) \
    _GEN_SET_FUNCTION(_cfg_type, _name, _member, _vtype)  \
    _GEN_GET_FUNCTION(_cfg_type, _name, _member, _vtype)

#define _GEN_STR_FUNCTIONS(_cfg_type, _name, _member) \
    _GEN_STR_SET_FUNCTION(_cfg_type, _name, _member)  \
    _GEN_GET_FUNCTION(_cfg_type, _name, _member, const char *)

struct rp_cfg_log_s {
    lzlog_level level;
    lzlog_type  type;
    char      * path;
    char      * logfmt;
    int         facility;
};

struct rp_cfg_rule_s {
    char           * name;            /**< the name of the rule */
    rule_type        type;            /**< what type of rule this is (regex/exact/glob) */
    lb_method        lb_method;       /**< method of load-balacinging (defaults to RTT) */
    char           * matchstr;        /**< the uri to match on */
    rp_cfg_headers * headers;         /**< headers which are added to the backend request */
    lztq           * downstreams;     /**< list of downstream names (as supplied by downstream_cfg_t->name */
    rp_cfg_log     * req_log_cfg;     /**< request logging config */
    rp_cfg_log     * err_log_cfg;     /**< error logging config */
    bool             passthrough;     /**< if set to true, a pipe between the upstream and downstream is established */
    bool             allow_redirect;  /**< if true, the downstream can send a redirect to connect to a different downstream */
    lztq           * redirect_filter; /**< a list of hostnames that redirects are can connect to */
    int              has_up_read_timeout;
    int              has_up_write_timeout;
    struct timeval   up_read_timeout;
    struct timeval   up_write_timeout;
};

/**
 * @brief a configuration structure representing a single x509 extension header.
 *
 */
struct rp_cfg_x509_ext_s {
    char * name;                 /**< the name of the header */
    char * oid;                  /**< the oid of the x509 extension to pull */
};

struct rp_cfg_ssl_crl_s {
    char         * filename;
    char         * dirname;
    struct timeval reload_timer;
};

/**
 * @brief which headers to add to the downstream request if avail.
 */
struct rp_cfg_headers_s {
    bool   x_forwarded_for;
    bool   x_ssl_subject;
    bool   x_ssl_issuer;
    bool   x_ssl_notbefore;
    bool   x_ssl_notafter;
    bool   x_ssl_sha1;
    bool   x_ssl_serial;
    bool   x_ssl_cipher;
    bool   x_ssl_certificate;
    lztq * x509_exts;
};

/**
 * @brief configuration for a single downstream.
 */
struct rp_cfg_downstream_s {
    bool     enabled;               /**< true if server is enabled */
    char   * name;                  /**< the name of this downstream. the name is used as an identifier for rules */
    char   * host;                  /**< the hostname of the downstream */
    uint16_t port;                  /**< the port of the downstream */
    int      n_connections;         /**< number of connections to keep established */
    size_t   high_watermark;        /**< if the number of bytes pending on the output side
                                     * of the socket reaches this number, the proxy stops
                                     * reading from the upstream until all data has been written. */
    struct timeval retry_ival;      /**< retry timer if the downstream connection goes down */
    struct timeval read_timeout;
    struct timeval write_timeout;
};


struct rp_cfg_vhost_s {
    rp_cfg_ssl     * ssl_cfg;
    lztq           * rule_cfgs;         /**< list of rule_cfg_t's */
    lztq           * rules;             /* list of rule_t's */
    char           * server_name;
    lztq           * aliases;           /**< other hostnames this vhost is associated with */
    lztq           * strip_hdrs;        /**< headers to strip out from downstream responses */
    rp_cfg_log     * req_log_cfg;       /* request logging configuration */
    rp_cfg_log     * err_log_cfg;       /* error logging configuration */
    rp_cfg_headers * headers;           /**< headers which are added to the backend request */
};

/**
 * @brief configuration for a single listening frontend server.
 */
struct rp_cfg_server_s {
    char   * bind_addr;                 /**< address to bind on */
    uint16_t bind_port;                 /**< port to bind on */
    int      num_threads;               /**< number of worker threads to start */
    int      max_pending;               /**< max pending requests before new connections are dropped */
    int      listen_backlog;            /**< listen backlog */
    size_t   high_watermark;            /**< upstream high-watermark */

    struct timeval read_timeout;        /**< time to wait for reading before client is dropped */
    struct timeval write_timeout;       /**< time to wait for writing before client is dropped */
    struct timeval pending_timeout;     /**< time to wait for a downstream to become available for a connection */

    rp_cfg     * rproxy_cfg;            /**< parent rproxy configuration */
    rp_cfg_ssl * ssl_cfg;               /**< if enabled, the ssl configuration */
    lztq       * downstreams;           /**< list of downstream_cfg_t's */
    lztq       * vhosts;                /**< list of vhost_cfg_t's */
    rp_cfg_log * req_log_cfg;
    rp_cfg_log * err_log_cfg;

    bool server_nagle;                  /**< disable/enable nagle for listening sockets */
    bool client_nagle;                  /**< disable/enable nagle for upstream sockets */
    bool downstream_nagle;              /**< disable/enable nagle for downstream sockets */
};



/**
 * @brief This is a structure that is filled during the configuration parsing
 *        stage. The information contains the various resources (file descriptors
 *        and such) that would be needed for the proxy to run optimally.
 *
 *        The idea is to warn the administrator that his system limits
 *        may impact the performance of the service.
 */
struct rp_cfg_rusage_s {
    unsigned int total_num_connections; /**< the total of all downstream connections */
    unsigned int total_num_threads;     /**< the total threads which will spawn */
    unsigned int total_max_pending;     /**< the total of configured max-pending connections */
};

/**
 * @brief main configuration structure.
 */
struct rp_cfg_s {
    bool         daemonize;             /**< should proxy run in background */
    int          mem_trimsz;
    int          max_nofile;            /**< max number of open file descriptors */
    char       * rootdir;               /**< root dir to daemonize */
    char       * user;                  /**< user to run as */
    char       * group;                 /**< group to run as */
    lztq       * servers;               /**< list of server_cfg_t's */
    rp_cfg_log * log;                   /**< generic log configuration */
    rp_cfg_log   rusage;                /**< the needed resource totals */
    char       * file_buffer;           /**< copy of the config file in mem */
};

/* rp_cfg_rusage generated functions */
_GEN_FUNCTIONS(rusage, total_n_conns, total_num_connections, unsigned int)
_GEN_FUNCTIONS(rusage, total_n_threads, total_num_threads, unsigned int)
_GEN_FUNCTIONS(rusage, total_max_pending, total_max_pending, unsigned int)

/* rp_cfg_log generated functions */
_GEN_FUNCTIONS(log, level, level, lzlog_level)
_GEN_FUNCTIONS(log, type, type, lzlog_type)
_GEN_FUNCTIONS(log, facility, facility, int)
_GEN_STR_FUNCTIONS(log, logfmt, logfmt)
_GEN_STR_FUNCTIONS(log, path, path)

/* rp_cfg_rule generated functions */
_GEN_FUNCTIONS(rule, type, type, rule_type)
_GEN_FUNCTIONS(rule, lb_method, lb_method, lb_method)
_GEN_FUNCTIONS(rule, headers_cfg, headers, rp_cfg_headers *)
_GEN_FUNCTIONS(rule, downstreams, downstreams, lztq *)
_GEN_FUNCTIONS(rule, req_log_cfg, req_log_cfg, rp_cfg_log *)
_GEN_FUNCTIONS(rule, err_log_cfg, err_log_cfg, rp_cfg_log *)
_GEN_FUNCTIONS(rule, passthrough, passthrough, bool)
_GEN_FUNCTIONS(rule, allow_redirect, allow_redirect, bool)
_GEN_FUNCTIONS(rule, redirect_filter, redirect_filter, lztq *)
_GEN_FUNCTIONS(rule, has_up_read_timeout, has_up_read_timeout, int)
_GEN_FUNCTIONS(rule, has_up_write_timeout, has_up_write_timeout, int)
_GEN_STR_FUNCTIONS(rule, name, name)
_GEN_STR_FUNCTIONS(rule, matchstr, matchstr)

/* rp_cfg_x509_ext generated functions */
_GEN_STR_FUNCTIONS(x509_ext, name, name)
_GEN_STR_FUNCTIONS(x509_ext, oid, oid)

/* rp_cfg_ssl_crl generated functions */
_GEN_STR_FUNCTIONS(ssl_crl, filename, filename)
_GEN_STR_FUNCTIONS(ssl_crl, dirname, dirname)

/* rp_cfg_headers generated functions */
_GEN_FUNCTIONS(headers, x_forwarded_for, x_forwarded_for, bool)
_GEN_FUNCTIONS(headers, x_ssl_subject, x_ssl_subject, bool)
_GEN_FUNCTIONS(headers, x_ssl_issuer, x_ssl_issuer, bool)
_GEN_FUNCTIONS(headers, x_ssl_notbefore, x_ssl_notbefore, bool)
_GEN_FUNCTIONS(headers, x_ssl_notafter, x_ssl_notafter, bool)
_GEN_FUNCTIONS(headers, x_ssl_sha1, x_ssl_sha1, bool)
_GEN_FUNCTIONS(headers, x_ssl_serial, x_ssl_serial, bool)
_GEN_FUNCTIONS(headers, x_ssl_cipher, x_ssl_cipher, bool)
_GEN_FUNCTIONS(headers, x_ssl_certificate, x_ssl_certificate, bool)
_GEN_FUNCTIONS(headers, x509_exts, x509_exts, lztq *)

/* rp_cfg_downstream generated functions */
_GEN_FUNCTIONS(downstream, enabled, enabled, bool)
_GEN_FUNCTIONS(downstream, port, port, uint16_t)
_GEN_FUNCTIONS(downstream, n_connections, n_connections, int)
_GEN_FUNCTIONS(downstream, high_wm, high_watermark, size_t)
_GEN_STR_FUNCTIONS(downstream, name, name)
_GEN_STR_FUNCTIONS(downstream, host, host)

/* rp_cfg_vhost generated functions */
_GEN_FUNCTIONS(vhost, ssl_cfg, ssl_cfg, rp_cfg_ssl *)
_GEN_FUNCTIONS(vhost, rule_cfgs, rule_cfgs, lztq *)
_GEN_FUNCTIONS(vhost, rules, rules, lztq *)
_GEN_FUNCTIONS(vhost, aliases, aliases, lztq *)
_GEN_FUNCTIONS(vhost, strip_hdrs, strip_hdrs, lztq *)
_GEN_FUNCTIONS(vhost, req_log_cfg, req_log_cfg, rp_cfg_log *)
_GEN_FUNCTIONS(vhost, err_log_cfg, err_log_cfg, rp_cfg_log *)
_GEN_FUNCTIONS(vhost, headers_cfg, headers, rp_cfg_headers *)
_GEN_STR_FUNCTIONS(vhost, server_name, server_name)

/* rp_cfg_server generated functions */
_GEN_STR_FUNCTIONS(server, bind_addr, bind_addr)
_GEN_FUNCTIONS(server, bind_port, bind_port, uint16_t)
_GEN_FUNCTIONS(server, n_threads, num_threads, int)
_GEN_FUNCTIONS(server, max_pending, max_pending, int)
_GEN_FUNCTIONS(server, listen_backlog, listen_backlog, int)
_GEN_FUNCTIONS(server, high_wm, high_watermark, size_t)
_GEN_FUNCTIONS(server, rp_cfg, rproxy_cfg, rp_cfg *)
_GEN_FUNCTIONS(server, ssl_cfg, ssl_cfg, rp_cfg_ssl *)
_GEN_FUNCTIONS(server, downstream_cfgs, downstreams, lztq *)
_GEN_FUNCTIONS(server, vhost_cfgs, vhosts, lztq *)
_GEN_FUNCTIONS(server, req_log_cfg, req_log_cfg, rp_cfg_log *)
_GEN_FUNCTIONS(server, err_log_cfg, err_log_cfg, rp_cfg_log *)
_GEN_FUNCTIONS(server, server_nagle, server_nagle, bool)
_GEN_FUNCTIONS(server, client_nagle, client_nagle, bool)
_GEN_FUNCTIONS(server, downstream_nagle, downstream_nagle, bool);

/* evhtp_ssl_cfg generated functions */
_GEN_STR_FUNCTIONS(ssl, pemfile, pemfile);
_GEN_STR_FUNCTIONS(ssl, key, privfile);
_GEN_STR_FUNCTIONS(ssl, ca, cafile);
_GEN_STR_FUNCTIONS(ssl, capath, capath);
_GEN_STR_FUNCTIONS(ssl, ciphers, ciphers);
_GEN_FUNCTIONS(ssl, ctx_timeout, ssl_ctx_timeout, int);
_GEN_FUNCTIONS(ssl, verify_peer, verify_peer, int);
_GEN_FUNCTIONS(ssl, verify_depth, verify_depth, int);
_GEN_FUNCTIONS(ssl, verifyfn, x509_verify_cb, evhtp_ssl_verify_cb);
_GEN_FUNCTIONS(ssl, x509_chk_issuedfn, x509_chk_issued_cb, evhtp_ssl_chk_issued_cb);
_GEN_FUNCTIONS(ssl, cache_type, scache_type, evhtp_ssl_scache_type);
_GEN_FUNCTIONS(ssl, cache_size, scache_size, long);
_GEN_FUNCTIONS(ssl, cache_timeout, scache_timeout, long);
_GEN_FUNCTIONS(ssl, opts, ssl_opts, long);


#define DEFAULT_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:RC4-SHA:RC4-MD5:ECDHE-RSA-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:AES128-SHA"

static cfg_opt_t     _rp_downstream_opts[] = {
    CFG_BOOL("enabled",           cfg_true,       CFGF_NONE),
    CFG_STR("addr",               NULL,           CFGF_NODEFAULT),
    CFG_INT("port",               0,              CFGF_NODEFAULT),
    CFG_INT("connections",        1,              CFGF_NONE),
    CFG_INT("high-watermark",     0,              CFGF_NONE),
    CFG_INT_LIST("read-timeout",  "{ 0, 0 }",     CFGF_NONE),
    CFG_INT_LIST("write-timeout", "{ 0, 0 }",     CFGF_NONE),
    CFG_INT_LIST("retry",         "{ 0, 50000 }", CFGF_NONE),
    CFG_END()
};

static cfg_opt_t     _rp_ssl_crl_opts[] = {
    CFG_STR("file",        NULL,         CFGF_NONE),
    CFG_STR("dir",         NULL,         CFGF_NONE),
    CFG_INT_LIST("reload", "{ 10, 0  }", CFGF_NONE),
    CFG_END()
};

static cfg_opt_t     _rp_ssl_x509_ext_opts[] = {
    CFG_STR("name", NULL, CFGF_NONE),
    CFG_STR("oid",  NULL, CFGF_NONE),
    CFG_END()
};

static cfg_opt_t     _rp_ssl_opts[] = {
    CFG_BOOL("enabled",           cfg_false,        CFGF_NONE),
    CFG_STR_LIST("protocols-on",  "{ALL}",          CFGF_NONE),
    CFG_STR_LIST("protocols-off", NULL,             CFGF_NONE),
    CFG_STR("cert",               NULL,             CFGF_NONE),
    CFG_STR("key",                NULL,             CFGF_NONE),
    CFG_STR("ca",                 NULL,             CFGF_NONE),
    CFG_STR("capath",             NULL,             CFGF_NONE),
    CFG_STR("ciphers",            DEFAULT_CIPHERS,  CFGF_NONE),
    CFG_BOOL("verify-peer",       cfg_false,        CFGF_NONE),
    CFG_BOOL("enforce-peer-cert", cfg_false,        CFGF_NONE),
    CFG_INT("verify-depth",       0,                CFGF_NONE),
    CFG_INT("context-timeout",    172800,           CFGF_NONE),
    CFG_BOOL("cache-enabled",     cfg_true,         CFGF_NONE),
    CFG_INT("cache-timeout",      1024,             CFGF_NONE),
    CFG_INT("cache-size",         65535,            CFGF_NONE),
    CFG_SEC("crl",                _rp_ssl_crl_opts, CFGF_NODEFAULT),
    CFG_END()
};

static cfg_opt_t     _rp_log_opts[] = {
    CFG_BOOL("enabled", cfg_false,                   CFGF_NONE),
    CFG_STR("output",   "file:/dev/stdout",          CFGF_NONE),
    CFG_STR("level",    "error",                     CFGF_NONE),
    CFG_STR("format",   "{SRC} {HOST} {URI} {HOST}", CFGF_NONE),
    CFG_END()
};

static cfg_opt_t     _rp_headers_opts[] = {
    CFG_BOOL("x-forwarded-for",   cfg_true,              CFGF_NONE),
    CFG_BOOL("x-ssl-subject",     cfg_false,             CFGF_NONE),
    CFG_BOOL("x-ssl-issuer",      cfg_false,             CFGF_NONE),
    CFG_BOOL("x-ssl-notbefore",   cfg_false,             CFGF_NONE),
    CFG_BOOL("x-ssl-notafter",    cfg_false,             CFGF_NONE),
    CFG_BOOL("x-ssl-serial",      cfg_false,             CFGF_NONE),
    CFG_BOOL("x-ssl-sha1",        cfg_false,             CFGF_NONE),
    CFG_BOOL("x-ssl-cipher",      cfg_false,             CFGF_NONE),
    CFG_BOOL("x-ssl-certificate", cfg_true,              CFGF_NONE),
    CFG_SEC("x509-extension",     _rp_ssl_x509_ext_opts, CFGF_MULTI),
    CFG_END()
};

static cfg_opt_t     _rp_rule_opts[] = {
    CFG_STR("uri-match",                   NULL,             CFGF_NODEFAULT),
    CFG_STR("uri-gmatch",                  NULL,             CFGF_NODEFAULT),
    CFG_STR("uri-rmatch",                  NULL,             CFGF_NODEFAULT),
    CFG_STR_LIST("downstreams",            NULL,             CFGF_NODEFAULT),
    CFG_STR("lb-method",                   "rtt",            CFGF_NONE),
    CFG_SEC("headers",                     _rp_headers_opts, CFGF_NODEFAULT),
    CFG_INT_LIST("upstream-read-timeout",  NULL,             CFGF_NODEFAULT),
    CFG_INT_LIST("upstream-write-timeout", NULL,             CFGF_NODEFAULT),
    CFG_BOOL("passthrough",                cfg_false,        CFGF_NONE),
    CFG_BOOL("allow-redirect",             cfg_false,        CFGF_NONE),
    CFG_STR_LIST("redirect-filter",        NULL,             CFGF_NODEFAULT),
    CFG_END()
};

static cfg_opt_t     _rp_vhost_opts[] = {
    CFG_STR_LIST("aliases",       NULL,             CFGF_NONE),
    CFG_STR_LIST("strip-headers", "{}",             CFGF_NONE),
    CFG_SEC("ssl",                _rp_ssl_opts,     CFGF_NODEFAULT),
    CFG_SEC("logging",            _rp_log_opts,     CFGF_NODEFAULT),
    CFG_SEC("headers",            _rp_headers_opts, CFGF_NODEFAULT),
    CFG_SEC("rule",               _rp_rule_opts,    CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
    CFG_END()
};

static cfg_opt_t     _rp_server_opts[] = {
    CFG_STR("addr",                      "127.0.0.1",         CFGF_NONE),
    CFG_INT("port",                      8080,                CFGF_NONE),
    CFG_INT("threads",                   4,                   CFGF_NONE),
    CFG_INT_LIST("read-timeout",         "{ 0, 0 }",          CFGF_NONE),
    CFG_INT_LIST("write-timeout",        "{ 0, 0 }",          CFGF_NONE),
    CFG_INT_LIST("pending-timeout",      "{ 0, 0 }",          CFGF_NONE),
    CFG_INT("high-watermark",            0,                   CFGF_NONE),
    CFG_INT("max-pending",               0,                   CFGF_NONE),
    CFG_INT("backlog",                   1024,                CFGF_NONE),
    CFG_SEC("downstream",                _rp_downstream_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
    CFG_SEC("vhost",                     _rp_vhost_opts,      CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
    CFG_SEC("ssl",                       _rp_ssl_opts,        CFGF_NODEFAULT),
    CFG_SEC("logging",                   _rp_log_opts,        CFGF_NODEFAULT),
    CFG_BOOL("disable-server-nagle",     cfg_false,           CFGF_NONE),
    CFG_BOOL("disable-client-nagle",     cfg_false,           CFGF_NONE),
    CFG_BOOL("disable-downstream-nagle", cfg_false,           CFGF_NONE),
    CFG_END()
};

static cfg_opt_t     _rp_cfg_opts[] = {
    CFG_BOOL(_DAEMONIZE_K, cfg_false,       CFGF_NONE),
    CFG_STR(_ROOTDIR_K,    "/tmp",          CFGF_NONE),
    CFG_STR(_USER_K,       NULL,            CFGF_NONE),
    CFG_STR(_GROUP_K,      NULL,            CFGF_NONE),
    CFG_INT(_MAX_NOFILE_K, 1024,            CFGF_NONE),
    CFG_SEC(_SERVER_K,     _rp_server_opts, CFGF_MULTI),
    CFG_END()
};

static rp_cfg_rusage _rusage = { 0, 0, 0 };

void
rp_cfg_set_user(rp_cfg * cfg, const char * user) {
    assert(cfg != NULL);

    free(cfg->user); cfg->user = NULL;

    if (user != NULL) {
        cfg->user = strdup(user);
    }
}

void
rp_cfg_set_group(rp_cfg * cfg, const char * group) {
    assert(cfg != NULL);

    free(cfg->group); cfg->group = NULL;

    if (group != NULL) {
        cfg->group = strdup(group);
    }
}

void
rp_cfg_set_rootdir(rp_cfg * cfg, const char * rootdir) {
    assert(cfg != NULL);

    free(cfg->rootdir); cfg->rootdir = NULL;

    if (rootdir) {
        cfg->rootdir = strdup(rootdir);
    }
}

void
rp_cfg_set_max_nofile(rp_cfg * cfg, const int nofile) {
    assert(cfg != NULL);

    cfg->max_nofile = nofile;
}

void
rp_cfg_set_daemonize(rp_cfg * cfg, const bool daemonize) {
    assert(cfg != NULL);

    cfg->daemonize = daemonize;
}

void
rp_cfg_free(rp_cfg * cfg) {
    if (!cfg) {
        return;
    }

    rp_cfg_log_free(cfg->log);

    free(cfg->file_buffer);
    free(cfg->rootdir);
    free(cfg->user);
    free(cfg->group);

    lztq_free(cfg->servers);

    free(cfg);
}

void
rp_cfg_rule_free(rp_cfg_rule * cfg) {
    if (!cfg) {
        return;
    }

    free(cfg->name);
    free(cfg->matchstr);

    rp_cfg_headers_free(cfg->headers);
    rp_cfg_log_free(cfg->req_log_cfg);
    rp_cfg_log_free(cfg->err_log_cfg);

    lztq_free(cfg->redirect_filter);

    free(cfg);
}

void
rp_cfg_vhost_free(rp_cfg_vhost * cfg) {
    if (!cfg) {
        return;
    }

    lztq_free(cfg->rule_cfgs);
    lztq_free(cfg->rules);
    lztq_free(cfg->aliases);
    lztq_free(cfg->strip_hdrs);

    rp_cfg_headers_free(cfg->headers);
    rp_cfg_log_free(cfg->req_log_cfg);
    rp_cfg_log_free(cfg->err_log_cfg);

    free(cfg->ssl_cfg);
    free(cfg->server_name);

    free(cfg);
}

void
rp_cfg_downstream_free(rp_cfg_downstream * cfg) {
    if (!cfg) {
        return;
    }

    free(cfg->name);
    free(cfg->host);
    free(cfg);
}

rp_cfg *
rp_cfg_new(void) {
    rp_cfg * rp_cfg_ctx;

    if (!(rp_cfg_ctx = calloc(sizeof(rp_cfg), 1))) {
        _FAIL;
    }

    if (!(rp_cfg_ctx->servers = lztq_new())) {
        _FAIL;
    }

    return rp_cfg_ctx;
}

rp_cfg_vhost *
rp_cfg_vhost_new(void) {
    rp_cfg_vhost * cfg;

    if (!(cfg = calloc(sizeof(rp_cfg_vhost), 1))) {
        _FAIL;
    }

    if (!(cfg->rule_cfgs = lztq_new())) {
        _FAIL;
    }

    if (!(cfg->rules = lztq_new())) {
        _FAIL;
    }

    if (!(cfg->aliases = lztq_new())) {
        _FAIL;
    }

    return cfg;
}

rp_cfg_server *
rp_cfg_server_new(void) {
    rp_cfg_server * svr_cfg;

    if (!(svr_cfg = calloc(sizeof(rp_cfg_server), 1))) {
        _FAIL;
    }

    if (!(svr_cfg->downstreams = lztq_new())) {
        _FAIL;
    }

    if (!(svr_cfg->vhosts = lztq_new())) {
        _FAIL;
    }

    return svr_cfg;
}

rp_cfg_downstream *
rp_cfg_downstream_new(void) {
    return (rp_cfg_downstream *)calloc(sizeof(rp_cfg_downstream), 1);
}

rp_cfg_ssl *
rp_cfg_ssl_new(void) {
    return (rp_cfg_ssl *)calloc(sizeof(evhtp_ssl_cfg_t), 1);
}

rp_cfg_rule *
rp_cfg_rule_new(void) {
    rp_cfg_rule * cfg;

    if (!(cfg = calloc(sizeof(rp_cfg_rule), 1))) {
        _FAIL;
    }

    if (!(cfg->downstreams = lztq_new())) {
        _FAIL;
    }

    return cfg;
}

static struct {
    int          facility;
    const char * str;
} facility_strmap[] = {
    { LOG_KERN,     "kern"     },
    { LOG_USER,     "user"     },
    { LOG_MAIL,     "mail"     },
    { LOG_DAEMON,   "daemon"   },
    { LOG_AUTH,     "auth"     },
    { LOG_SYSLOG,   "syslog"   },
    { LOG_LPR,      "lptr"     },
    { LOG_NEWS,     "news"     },
    { LOG_UUCP,     "uucp"     },
    { LOG_CRON,     "cron"     },
    { LOG_AUTHPRIV, "authpriv" },
    { LOG_FTP,      "ftp"      },
    { LOG_LOCAL0,   "local0"   },
    { LOG_LOCAL1,   "local1"   },
    { LOG_LOCAL2,   "local2"   },
    { LOG_LOCAL3,   "local3"   },
    { LOG_LOCAL4,   "local4"   },
    { LOG_LOCAL5,   "local5"   },
    { LOG_LOCAL6,   "local6"   },
    { LOG_LOCAL7,   "local7"   },
    { -1,           NULL       }
};

/**
 * @brief Convert the config value of "lb-method" to a lb_method enum type.
 *
 * @param lbstr
 *
 * @return the lb_method enum
 */
static lb_method
lbstr_to_lbtype(const char * lbstr) {
    if (!lbstr) {
        return lb_method_rtt;
    }

    if (!strcasecmp(lbstr, "rtt")) {
        return lb_method_rtt;
    }

    if (!strcasecmp(lbstr, "roundrobin")) {
        return lb_method_rr;
    }

    if (!strcasecmp(lbstr, "random")) {
        return lb_method_rand;
    }

    if (!strcasecmp(lbstr, "most-idle")) {
        return lb_method_most_idle;
    }

    if (!strcasecmp(lbstr, "none")) {
        return lb_method_none;
    }

    return lb_method_rtt;
}

static rp_cfg_ssl *
_cfg_parse_ssl(cfg_t * cfg) {
    rp_cfg_ssl * ssl_cfg;
    long         ssl_opts        = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
    int          ssl_verify_mode = 0;
    int          proto_on_count;
    int          proto_off_count;
    int          i;
    struct stat  file_stat;

    if (cfg == NULL) {
        return NULL;
    }

    if (cfg_getbool(cfg, _ENABLED_K) == cfg_false) {
        return NULL;
    }

    if (!(ssl_cfg = rp_cfg_ssl_new())) {
        _FAIL;
    }

    rp_cfg_ssl_set_pemfile(ssl_cfg, cfg_getstr(cfg, _SSL_CERT_K));
    rp_cfg_ssl_set_key(ssl_cfg, cfg_getstr(cfg, _SSL_KEY_K));
    rp_cfg_ssl_set_ca(ssl_cfg, cfg_getstr(cfg, _SSL_CA_K));
    rp_cfg_ssl_set_capath(ssl_cfg, cfg_getstr(cfg, _SSL_CAPATH_K));
    rp_cfg_ssl_set_ciphers(ssl_cfg, cfg_getstr(cfg, _SSL_CIPHERS_K));
    rp_cfg_ssl_set_ctx_timeout(ssl_cfg, cfg_getint(cfg, _SSL_CTX_TIMEOUT_K));

    if (cfg_getbool(cfg, _SSL_VERIFY_PEER_K) == cfg_true) {
        ssl_verify_mode |= SSL_VERIFY_PEER;
    }

    if (cfg_getbool(cfg, _SSL_ENFORCE_PEER_CERT_K) == cfg_true) {
        ssl_verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    if (ssl_verify_mode != 0) {
        rp_cfg_ssl_set_verify_peer(ssl_cfg, ssl_verify_mode);
        rp_cfg_ssl_set_verify_depth(ssl_cfg, cfg_getint(cfg, _SSL_VERIFY_DEPTH_K));
        rp_cfg_ssl_set_verifyfn(ssl_cfg, ssl_x509_verifyfn);
        rp_cfg_ssl_set_x509_chk_issuedfn(ssl_cfg, NULL);
    }

    if (cfg_getbool(cfg, _SSL_CACHE_ENABLED_K) == cfg_true) {
        rp_cfg_ssl_set_cache_type(ssl_cfg, evhtp_ssl_scache_type_internal);
        rp_cfg_ssl_set_cache_size(ssl_cfg, cfg_getint(cfg, _SSL_CACHE_SIZE_K));
        rp_cfg_ssl_set_cache_timeout(ssl_cfg, cfg_getint(cfg, _SSL_CACHE_TIMEOUT_K));
    }

    proto_on_count  = cfg_size(cfg, _SSL_PROTO_ON_K);
    proto_off_count = cfg_size(cfg, _SSL_PROTO_OFF_K);

    for (i = 0; i < proto_on_count; i++) {
        const char * proto_str = cfg_getnstr(cfg, _SSL_PROTO_ON_K, i);

        if (!strcasecmp(proto_str, "SSLv2")) {
            ssl_opts &= ~SSL_OP_NO_SSLv2;
        } else if (!strcasecmp(proto_str, "SSLv3")) {
            ssl_opts &= ~SSL_OP_NO_SSLv3;
        } else if (!strcasecmp(proto_str, "TLSv1")) {
            ssl_opts &= ~SSL_OP_NO_TLSv1;
        } else if (!strcasecmp(proto_str, "ALL")) {
            ssl_opts = 0;
        }
    }

    for (i = 0; i < proto_off_count; i++) {
        const char * proto_str = cfg_getnstr(cfg, "protocols-off", i);

        if (!strcasecmp(proto_str, "SSLv2")) {
            ssl_opts |= SSL_OP_NO_SSLv2;
        } else if (!strcasecmp(proto_str, "SSLv3")) {
            ssl_opts |= SSL_OP_NO_SSLv3;
        } else if (!strcasecmp(proto_str, "TLSv1")) {
            ssl_opts |= SSL_OP_NO_TLSv1;
        } else if (!strcasecmp(proto_str, "ALL")) {
            ssl_opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
        }
    }

    rp_cfg_set_ssl_opts(ssl_cfg, ssl_opts);

    if (cfg_getsec(cfg, _SSL_CRL_K)) {
        rp_cfg_ssl_crl * crl_config;
        cfg_t          * crl_cfg;

        crl_cfg = cfg_getsec(cfg, _SSL_CRL_K);
        assert(crl_cfg != NULL);

        if (!(crl_config = calloc(sizeof(rp_cfg_ssl_crl), 1))) {
            fprintf(stderr, "Could not allocate crl cfg %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if (cfg_getstr(crl_cfg, "file")) {
            crl_config->filename = strdup(cfg_getstr(crl_cfg, "file"));

            if (stat(crl_config->filename, &file_stat) == -1 || !S_ISREG(file_stat.st_mode)) {
                fprintf(stderr, "Cannot find CRL file '%s'\n", crl_config->filename);
                exit(EXIT_FAILURE);
            }
        }

        if (cfg_getstr(crl_cfg, "dir")) {
            crl_config->dirname = strdup(cfg_getstr(crl_cfg, "dir"));

            if (stat(crl_config->dirname, &file_stat) != 0 || !S_ISDIR(file_stat.st_mode)) {
                fprintf(stderr, "Cannot find CRL directory '%s'\n", crl_config->dirname);
                exit(EXIT_FAILURE);
            }
        }

        crl_config->reload_timer.tv_sec  = cfg_getnint(crl_cfg, "reload", 0);
        crl_config->reload_timer.tv_usec = cfg_getnint(crl_cfg, "reload", 1);

        /* at the moment evhtp does not give us an area where we can store this
         * type of information without breaking the configuration structure. But
         * it does have an optional user-supplied arguments, which we use here
         * to store our CRL configuration.
         */
        ssl_cfg->args = (void *)crl_config;
    }

    return ssl_cfg;
} /* _cfg_parse_ssl */

static rp_cfg_downstream *
_cfg_parse_downstream(cfg_t * cfg) {
    rp_cfg_downstream * ds_cfg;

    if (cfg == NULL) {
        _FAIL;
    }

    if (!(ds_cfg = rp_cfg_downstream_new())) {
        _FAIL;
    }

    rp_cfg_downstream_set_name(ds_cfg, cfg_title(cfg));
    rp_cfg_downstream_set_enabled(ds_cfg, cfg_getbool(cfg, _ENABLED_K));
    rp_cfg_downstream_set_host(ds_cfg, cfg_getstr(cfg, _ADDR_K));
    rp_cfg_downstream_set_port(ds_cfg, cfg_getint(cfg, _PORT_K));
    rp_cfg_downstream_set_n_connections(ds_cfg, cfg_getint(cfg, _N_CONNS_K));
    rp_cfg_downstream_set_high_wm(ds_cfg, cfg_getint(cfg, _HIGH_WM_K));

    rp_cfg_downstream_set_read_timeout(ds_cfg,
                                       cfg_getnint(cfg, _READ_TIMEOUT_K, 0),
                                       cfg_getnint(cfg, _READ_TIMEOUT_K, 1));

    rp_cfg_downstream_set_write_timeout(ds_cfg,
                                        cfg_getnint(cfg, _WRITE_TIMEOUT_K, 0),
                                        cfg_getnint(cfg, _WRITE_TIMEOUT_K, 1));

    rp_cfg_downstream_set_retry(ds_cfg,
                                cfg_getnint(cfg, _RETRY_K, 0),
                                cfg_getnint(cfg, _RETRY_K, 1));

    if (rp_cfg_downstream_get_enabled(ds_cfg) == true) {
        _rusage.total_num_connections +=
            rp_cfg_downstream_get_n_connections(ds_cfg);
    }

    return ds_cfg;
}

static rp_cfg_rule *
_cfg_parse_rule(cfg_t * cfg) {
    rp_cfg_rule * rule_cfg;
    const char  * matchstr;
    rule_type     rule_type;
    int           i;

    assert(cfg != NULL);

    if (!(rule_cfg = rp_cfg_rule_new())) {
        _FAIL;
    }

    rp_cfg_rule_set_name(rule_cfg, cfg_title(cfg));

    if ((matchstr = cfg_getstr(cfg, "uri-match"))) {
        rule_type = rule_type_exact;
    } else if ((matchstr = cfg_getstr(cfg, "uri-gmatch"))) {
        rule_type = rule_type_glob;
    } else if ((matchstr = cfg_getstr(cfg, "uri-rmatch"))) {
        rule_type = rule_type_regex;
    } else {
        fprintf(stderr, "Rule %s has no match statement!\n", cfg_title(cfg));
        _FAIL;
    }

    rp_cfg_rule_set_type(rule_cfg, rule_type);
    rp_cfg_rule_set_matchstr(rule_cfg, matchstr);
    rp_cfg_rule_set_passthrough(rule_cfg, cfg_getbool(cfg, "passthrough"));
    rp_cfg_rule_set_allow_redirect(rule_cfg, cfg_getbool(cfg, "allow-redirect"));
    rp_cfg_rule_set_lb_method(rule_cfg, lbstr_to_lbtype(cfg_getstr(cfg, "lb-method")));
    rp_cfg_rule_set_headers(rule_cfg, _cfg_parse_headers(rule_cfg, cfg_getsec(cfg, "headers")));

    rp_cfg_rule_set_upstream_read_timeout(rule_cfg,
                                          cfg_getnint(cfg, "upstream-read-timeout", 0),
                                          cfg_getnint(cfg, "upstream-read-timeout", 1));

    rp_cfg_rule_set_upstream_write_timeout(rule_cfg,
                                           cfg_getnint(cfg, "upstream-write-timeout", 0),
                                           cfg_getnint(cfg, "upstream-write-timeout", 1));

    for (i = 0; i < cfg_size(cfg, "downstreams"); i++) {
        char * ds_name;

        if (!(ds_name = strdup(cfg_getnstr(cfg, "downstreams", i)))) {
            _FAIL;
        }

        if (!lztq_append(rule_cfg->downstreams, ds_name, strlen(ds_name), free)) {
            _FAIL;
        }
    }

    if (rp_cfg_rule_get_allow_redirect(rule_cfg) == true &&
        cfg_size(cfg, "redirect-filter")) {
        int n_filters;

        n_filters = cfg_size(cfg, "redirect-filter");
        assert(n_filters > 0);

        if (!(rule_cfg->redirect_filter = lztq_new())) {
            _FAIL;
        }

        for (i = 0; i < n_filters; i++) {
            char * host_str;

            if (!(host_str = strdup(cfg_getnstr(cfg, "redirect-filter", i)))) {
                _FAIL;
            }

            if (!lztq_append(rule_cfg->redirect_filter, host_str,
                             strlen(host_str), free)) {
                _FAIL;
            }
        }
    }

    return rule_cfg;
} /* _cfg_parse_rule */

static rp_cfg_vhost *
_cfg_parse_vhost(cfg_t * cfg) {
    rp_cfg_vhost * vhost_cfg;
    cfg_t        * log_cfg;
    cfg_t        * req_log_cfg;
    cfg_t        * err_log_cfg;
    cfg_t        * headers_cfg;
    cfg_t        * default_rule_cfg;
    int            i;

    if (!(vhost_cfg = rp_cfg_vhost_new())) {
        _FAIL;
    }

    rp_cfg_vhost_set_server_name(vhost_cfg, cfg_title(cfg));
    rp_cfg_vhost_set_ssl_cfg(vhost_cfg, _cfg_parse_ssl(cfg_getsec(cfg, _SSL_K)));

    for (i = 0; i < cfg_size(cfg, _RULE_K); i++) {
        rp_cfg_rule * rule_cfg;

        if (!(rule_cfg = _cfg_parse_rule(cfg_getnsec(cfg, _RULE_K, i)))) {
            _FAIL;
        }

        if (!lztq_append(vhost_cfg->rule_cfgs, rule_cfg, 1, (void (*))rp_cfg_rule_free)) {
            _FAIL;
        }
    }

    for (i = 0; i < cfg_size(cfg, _ALIASES_K); i++) {
        char * name;

        if (!(name = strdup(cfg_getnstr(cfg, _ALIASES_K, i)))) {
            _FAIL;
        }

        if (!lztq_append(vhost_cfg->aliases, name, strlen(name), free)) {
            _FAIL;
        }
    }

    if (cfg_size(cfg, _STRIP_HDRS_K)) {
        if (!(vhost_cfg->strip_hdrs = lztq_new())) {
            _FAIL;
        }

        for (i = 0; i < cfg_size(cfg, _STRIP_HDRS_K); i++) {
            char * hdr_name;

            if (!(hdr_name = strdup(cfg_getnstr(cfg, _STRIP_HDRS_K, i)))) {
                _FAIL;
            }

            if (!lztq_append(vhost_cfg->strip_hdrs, hdr_name, strlen(hdr_name), free)) {
                _FAIL;
            }
        }
    }

    if ((log_cfg = cfg_getsec(cfg, _LOG_K))) {
        rp_cfg_log * request;
        rp_cfg_log * error;

        if (!(request = _cfg_parse_log(cfg_getsec(log_cfg, _REQUEST_LOG_K)))) {
            _FAIL;
        }

        if (!(error = _cfg_parse_log(cfg_getsec(log_cfg, _ERROR_LOG_K)))) {
            _FAIL;
        }

        rp_cfg_vhost_set_req_log_cfg(vhost_cfg, request);
        rp_cfg_vhost_set_err_log_cfg(vhost_cfg, error);
    }

    if ((headers_cfg = cfg_getsec(cfg, _HEADERS_K))) {
        rp_cfg_headers * headers;

        if (!(headers = _cfg_parse_headers(headers_cfg))) {
            _FAIL;
        }

        rp_cfg_vhost_set_headers_cfg(vhost_cfg, headers);
    }


    return vhost_cfg;
} /* _cfg_parse_vhost */

static rp_cfg_server *
_cfg_parse_server(cfg_t * cfg) {
    rp_cfg_server * svr_cfg;
    int             i;

    assert(cfg != NULL);

    if (!(svr_cfg = rp_cfg_server_new())) {
        _FAIL;
    }

    rp_cfg_server_set_bind_addr(svr_cfg, cfg_getstr(cfg, _ADDR_K));
    rp_cfg_server_set_bind_port(svr_cfg, cfg_getint(cfg, _PORT_K));
    rp_cfg_server_set_n_threads(svr_cfg, cfg_getint(cfg, _THREADS_K));
    rp_cfg_server_set_listen_backlog(svr_cfg, cfg_getint(cfg, _BACKLOG_K));
    rp_cfg_server_set_max_pending(svr_cfg, cfg_getint(cfg, _MAX_PENDING_K));
    rp_cfg_server_set_high_wm(svr_cfg, cfg_getint(cfg, _HIGH_WM_K));
    rp_cfg_server_set_server_nagle(svr_cfg, cfg_getbool(cfg, _DISABLE_SERVER_NAGLE_K));
    rp_cfg_server_set_client_nagle(svr_cfg, cfg_getbool(cfg, _DISABLE_CLIENT_NAGLE_K));
    rp_cfg_server_set_downstream_nagle(svr_cfg, cfg_getbool(cfg, _DISABLE_DOWNSTR_NAGLE_K));
    rp_cfg_server_set_ssl_cfg(svr_cfg, _cfg_parse_ssl(cfg_getsec(cfg, _SSL_K)));

    if (cfg_getsec(cfg, _LOG_K)) {
        cfg_t      * log_cfg = cfg_getsec(cfg, _LOG_K);
        rp_cfg_log * request;
        rp_cfg_log * error;

        if (!(request = _cfg_parse_log(cfg_getsec(log_cfg, _REQUEST_LOG_K)))) {
            _FAIL;
        }

        if (!(error = _cfg_parse_log(cfg_getsec(log_cfg, _ERROR_LOG_K)))) {
            _FAIL;
        }

        rp_cfg_server_set_req_log_cfg(svr_cfg, request);
        rp_cfg_server_set_err_log_cfg(svr_cfg, error);
    }

    rp_cfg_server_set_read_timeout(svr_cfg,
                                   cfg_getnint(cfg, _READ_TIMEOUT_K, 0),
                                   cfg_getnint(cfg, _READ_TIMEOUT_K, 1));

    rp_cfg_server_set_write_timeout(svr_cfg,
                                    cfg_getnint(cfg, _WRITE_TIMEOUT_K, 0),
                                    cfg_getnint(cfg, _WRITE_TIMEOUT_K, 1));

    rp_cfg_server_set_pending_timeout(svr_cfg,
                                      cfg_getnint(cfg, _PENDING_TIMEOUT_K, 0),
                                      cfg_getnint(cfg, _PENDING_TIMEOUT_K, 1));

    /* parse and insert all of the configured downstreams */
    for (i = 0; i < cfg_size(cfg, _DOWNSTREAM_K); i++) {
        rp_cfg_downstream * ds_cfg;

        ds_cfg = _cfg_parse_downstream(cfg_getnsec(cfg, _DOWNSTREAM_K, i));

        if (ds_cfg == NULL) {
            _FAIL;
        }

        if (!(lztq_append(svr_cfg->downstreams, ds_cfg, 1,
                          (void(*))rp_cfg_downstream_free))) {
            _FAIL;
        }
    }

    for (i = 0; i < cfg_size(cfg, _VHOST_K); i++) {
        rp_cfg_vhost * vhost_cfg;

        vhost_cfg = _cfg_parse_vhost(cfg_getnsec(cfg, _VHOST_K, i));

        if (vhost_cfg == NULL) {
            _FAIL;
        }

        if (!(lztq_append(svr_cfg->downstreams, vhost_cfg, 1,
                          (void(*))rp_cfg_vhost_free))) {
            _FAIL;
        }
    }

    _rusage.total_num_threads += rp_cfg_server_get_n_threads(svr_cfg);
    _rusage.total_max_pending += rp_cfg_server_get_max_pending(svr_cfg);

    return svr_cfg;
} /* _cfg_parse_server */

static rp_cfg *
_cfg_parse_ctx(cfg_t * cfg_ctx) {
    rp_cfg * rp_cfg_ctx;
    int      n_servers;
    int      i;

    assert(cfg_ctx != NULL);

    if (!(rp_cfg_ctx = rp_cfg_new())) {
        _FAIL;
    }

    rp_cfg_set_user(rp_cfg_ctx, cfg_getstr(cfg_ctx, _USER_K));
    rp_cfg_set_group(rp_cfg_ctx, cfg_getstr(cfg_ctx, _GROUP_K));
    rp_cfg_set_rootdir(rp_cfg_ctx, cfg_getstr(cfg_ctx, _ROOTDIR_K));
    rp_cfg_set_max_nofile(rp_cfg_ctx, cfg_getint(cfg_ctx, _MAX_NOFILE_K));
    rp_cfg_set_daemonize(rp_cfg_ctx, cfg_getbool(cfg_ctx, _DAEMONIZE_K));

    n_servers = cfg_size(cfg_ctx, _SERVER_K);
    assert(n_servers > 0);

    for (i = 0; i < n_servers; i++) {
        rp_cfg_server * svr_cfg;

        if (!(svr_cfg = _cfg_parse_server(cfg_getnsec(cfg_ctx, _SERVER_K, i)))) {
            _FAIL;
        }

        rp_server_cfg_set_rproxy_cfg(svr_cfg, rp_cfg_ctx);

        if (!(lztq_append(rp_cfg_ctx->servers, svr_cfg, 1, (void (*))rp_cfg_vhost_free))) {
            _FAIL;
        }
    }

    memcpy(&rp_cfg_ctx->rusage, &_rusage, sizeof(_rusage));

    return rp_cfg_ctx;
}

rp_cfg *
rp_cfg_parse(const char * filename) {
    cfg_t  * cfg_ctx;
    rp_cfg * rp_cfg;
    char   * file_buffer;
    FILE   * config_fp;
    long     file_sz;

    assert(filename != NULL);

    {
        if (!(config_fp = fopen(filename, "r"))) {
            _FAIL;
        }

        if (fseek(config_fp, 0, SEEK_END) != 0) {
            _FAIL;
        }

        if ((file_sz = ftell(config_fp)) == -1) {
            _FAIL;
        }

        if (!(file_buffer = malloc(sizeof(char) * (file_sz + 1)))) {
            _FAIL;
        }

        if (fseek(config_fp, 0, SEEK_SET) != 0) {
            _FAIL;
        }

        if (fread(file_buffer, sizeof(char), file_sz, config_fp) != file_sz) {
            _FAIL;
        }

        file_buffer[file_sz + 1] = '\0';

        fclose(config_fp);
    }


    if (!(cfg_ctx = cfg_init(_rp_cfg_opts, CFGF_NOCASE))) {
        _FAIL;
    }

    if (cfg_parse(cfg_ctx, filename) != 0) {
        _FAIL;
    }

    if (!(rp_cfg = _cfg_parse_ctx(cfg_ctx))) {
        _FAIL;
    }

    rp_cfg->file_buffer = file_buffer;

    return rp_cfg;
} /* rp_cfg_parse */

rp_cfg *
rp_cfg_dup(rp_cfg * in) {
    rp_cfg * out;
    cfg_t  * cfg_ctx;

    assert(in != NULL);
    assert(in->file_buffer != NULL);


    if (!(cfg_ctx = cfg_init(_rp_cfg_opts, CFGF_NOCASE))) {
        _FAIL;
    }

    if (cfg_parse_buf(cfg_ctx, in->file_buffer) != 0) {
        _FAIL;
    }

    if (!(out = _cfg_parse_ctx(cfg_ctx))) {
        _FAIL;
    }

    return out;
}

