#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_ip_blocker_shm.h"

#include <fcntl.h>           // For O_* constants
#include <sys/stat.h>        // For mode constants
#include <sys/mman.h>        // For shm_*

typedef struct {
	int enabled;

	ngx_array_t *name;

	ngx_array_t rules;
} ngx_http_ip_blocker_loc_conf_st;

typedef struct {
	int fd;

	/* fd may have been truncated behind our backs, be warned */
	ngx_ip_blocker_shm_st *addr;
	size_t size;

	uint32_t revision;
} ngx_http_ip_blocker_ruleset_st;

static ngx_int_t ngx_http_ip_blocker_init(ngx_conf_t *cf);

static void *ngx_http_ip_blocker_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ip_blocker_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static void ngx_http_ip_blocker_cleanup(void *data);

static ngx_inline ngx_int_t ngx_http_ip_blocker_remap(ngx_http_ip_blocker_ruleset_st *rule,
		ngx_log_t *log);
static ngx_inline ngx_int_t ngx_http_ip_blocker_check_shm(ngx_http_ip_blocker_ruleset_st *rule);

static ngx_int_t ngx_http_ip_blocker_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_ip_blocker_process_rule(ngx_http_request_t *r, ngx_http_ip_blocker_ruleset_st *rule);

static int ngx_http_ip_blocker_ip4_compare(const void *a, const void *b);
#if NGX_HAVE_INET6
static int ngx_http_ip_blocker_ip6_compare(const void *a, const void *b);
static int ngx_http_ip_blocker_ip6route_compare(const void *a, const void *b);
#endif /* NGX_HAVE_INET6 */

void ngx_ip_blocker_rwlock_rlock(ngx_ip_blocker_rwlock_st *rw);
void ngx_ip_blocker_rwlock_runlock(ngx_ip_blocker_rwlock_st *rw);

static ngx_command_t ngx_http_ip_blocker_module_commands[] = {
	{ ngx_string("ip_blocker"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_array_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_ip_blocker_loc_conf_st, name),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_ip_blocker_module_ctx = {
	NULL,                                /* preconfiguration */
	ngx_http_ip_blocker_init,            /* postconfiguration */

	NULL,                                /* create main configuration */
	NULL,                                /* init main configuration */

	NULL,                                /* create server configuration */
	NULL,                                /* merge server configuration */

	ngx_http_ip_blocker_create_loc_conf, /* create location configuration */
	ngx_http_ip_blocker_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_ip_blocker_module = {
	NGX_MODULE_V1,
	&ngx_http_ip_blocker_module_ctx,     /* module context */
	ngx_http_ip_blocker_module_commands, /* module directives */
	NGX_HTTP_MODULE,                     /* module type */
	NULL,                                /* init master */
	NULL,                                /* init module */
	NULL,                                /* init process */
	NULL,                                /* init thread */
	NULL,                                /* exit thread */
	NULL,                                /* exit process */
	NULL,                                /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_ip_blocker_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (!h) {
		return NGX_ERROR;
	}

	*h = ngx_http_ip_blocker_access_handler;
	return NGX_OK;
}

static void *ngx_http_ip_blocker_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_ip_blocker_loc_conf_st *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip_blocker_loc_conf_st));
	if (!conf) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->enabled = 0;
	 */

	conf->name = NGX_CONF_UNSET_PTR;
	return conf;
}

static char *ngx_http_ip_blocker_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	const ngx_http_ip_blocker_loc_conf_st *prev = parent;
	ngx_http_ip_blocker_loc_conf_st *conf = child;
	ngx_str_t *name;
	ngx_http_ip_blocker_ruleset_st *rule;
	ngx_pool_cleanup_t *cln;
	size_t i;
	struct stat sb;

	ngx_conf_merge_ptr_value(conf->name, prev->name, NULL);

	if (!conf->name || !conf->name->nelts) {
		return NGX_CONF_OK;
	}

	name = conf->name->elts;
	for (i = 0; i < conf->name->nelts; i++) {
		if (ngx_strcmp(name[i].data, "off") == 0) {
			return NGX_CONF_OK;
		}
	}

	if (ngx_array_init(&conf->rules, cf->pool, conf->name->nelts,
			sizeof(ngx_http_ip_blocker_ruleset_st)) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (!cln) {
		return NGX_CONF_ERROR;
	}

	cln->handler = ngx_http_ip_blocker_cleanup;
	cln->data = conf;

	conf->enabled = 1;

	for (i = 0; i < conf->name->nelts; i++) {
		rule = ngx_array_push(&conf->rules);
		if (!rule) {
			return NGX_CONF_ERROR;
		}

		ngx_memzero(rule, sizeof(ngx_http_ip_blocker_ruleset_st));
		rule->addr = MAP_FAILED;

		rule->fd = shm_open((const char *)name[i].data, O_RDWR, 0);
		if (rule->fd == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "shm_open failed");
			return NGX_CONF_ERROR;
		}

		if (fstat(rule->fd, &sb) == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "fstat failed");
			return NGX_CONF_ERROR;
		}

		rule->addr = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, rule->fd, 0);
		if (rule->addr == MAP_FAILED) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "mmap failed");
			return NGX_CONF_ERROR;
		}

		rule->size = sb.st_size;

		if (rule->size < sizeof(ngx_ip_blocker_shm_st)) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid shared memory");
			return NGX_CONF_ERROR;
		}

		ngx_ip_blocker_rwlock_rlock(&rule->addr->lock);

		rule->revision = rule->addr->revision;

		if (fstat(rule->fd, &sb) == -1) {
			ngx_ip_blocker_rwlock_runlock(&rule->addr->lock);

			ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "fstat failed");
			return NGX_CONF_ERROR;
		}

		if ((size_t)sb.st_size != rule->size) {
			/* shm has changed since we mmaped it (unlikely but possible) */

			/* runlock is called inside of remap iff NGX_ERROR is returned */
			if (ngx_http_ip_blocker_remap(rule, cf->log) != NGX_OK) {
				return NGX_CONF_ERROR;
			}
		} else if (ngx_http_ip_blocker_check_shm(rule) != NGX_OK) {
			ngx_ip_blocker_rwlock_runlock(&rule->addr->lock);

			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid shared memory");
			return NGX_CONF_ERROR;
		}

		ngx_ip_blocker_rwlock_runlock(&rule->addr->lock);
	}

	return NGX_CONF_OK;
}

static void ngx_http_ip_blocker_cleanup(void *data)
{
	ngx_http_ip_blocker_loc_conf_st *conf = data;
	ngx_http_ip_blocker_ruleset_st *rule;
	size_t i;

	rule = conf->rules.elts;
	for (i = 0; i < conf->rules.nelts; i++) {
		if (rule[i].addr != MAP_FAILED) {
			munmap(rule[i].addr, rule[i].size);

			rule[i].addr = MAP_FAILED;
			rule[i].size = 0; /* not strictly needed */
		}

		if (rule[i].fd != -1) {
			close(rule[i].fd);
		}
	}
}

/* rlock must be held before calling remap */
static ngx_inline ngx_int_t ngx_http_ip_blocker_remap(ngx_http_ip_blocker_ruleset_st *rule,
		ngx_log_t *log)
{
	ngx_ip_blocker_shm_st *addr;
	size_t size;
	struct stat sb;

	addr = rule->addr;
	size = rule->size;
	rule->addr = MAP_FAILED;
	rule->size = 0; /* not strictly needed */

	if (fstat(rule->fd, &sb) == -1) {
		ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "fstat failed");
		goto error;
	}

	rule->addr = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, rule->fd, 0);
	if (rule->addr == MAP_FAILED) {
		ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "mmap failed");
		goto error;
	}

	rule->size = sb.st_size;

	if (ngx_http_ip_blocker_check_shm(rule) != NGX_OK) {
		munmap(rule->addr, rule->size);
		rule->addr = MAP_FAILED;

		ngx_log_error(NGX_LOG_EMERG, log, 0, "invalid shared memory");
		goto error;
	}

	rule->revision = rule->addr->revision;

	munmap(addr, size);
	return NGX_OK;

error:
	if (!rule->size || rule->size >= sizeof(ngx_ip_blocker_shm_st)) {
		ngx_ip_blocker_rwlock_runlock(&addr->lock);
	} else {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "failed to release read lock");
	}

	munmap(addr, size);
	return NGX_ERROR;
}

static ngx_inline ngx_int_t ngx_http_ip_blocker_check_shm(ngx_http_ip_blocker_ruleset_st *rule)
{
	if (rule->size < sizeof(ngx_ip_blocker_shm_st)
		|| rule->size < sizeof(ngx_ip_blocker_shm_st)
			+ rule->addr->ip4.len + rule->addr->ip6.len + rule->addr->ip6route.len
		|| (rule->addr->ip4.len
			&& rule->addr->ip4.base < (ssize_t)sizeof(ngx_ip_blocker_shm_st))
		|| (rule->addr->ip6.len
			&& rule->addr->ip6.base < (ssize_t)sizeof(ngx_ip_blocker_shm_st))
		|| (rule->addr->ip6route.len
			&& rule->addr->ip6route.base < (ssize_t)sizeof(ngx_ip_blocker_shm_st))
		|| rule->addr->ip4.base + rule->addr->ip4.len > rule->size
		|| rule->addr->ip6.base + rule->addr->ip6.len > rule->size
		|| rule->addr->ip6route.base + rule->addr->ip6route.len > rule->size
		|| rule->addr->ip4.len % 4 != 0
		|| rule->addr->ip6.len % 16 != 0
		|| rule->addr->ip6route.len % 8 != 0) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http_ip_blocker_access_handler(ngx_http_request_t *r)
{
	ngx_http_ip_blocker_loc_conf_st *conf;
	ngx_http_core_loc_conf_t *clcf;
	ngx_http_ip_blocker_ruleset_st *rule;
	size_t i;
	ngx_int_t rc, out_rc;

	switch (r->connection->sockaddr->sa_family) {
		case AF_INET:
#if NGX_HAVE_INET6
		case AF_INET6:
#endif /* NGX_HAVE_INET6 */
			break;
		default:
			return NGX_DECLINED;
	}

	conf = ngx_http_get_module_loc_conf(r, ngx_http_ip_blocker_module);
	if (!conf || !conf->enabled) {
		return NGX_DECLINED;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	out_rc = NGX_DECLINED;

	rule = conf->rules.elts;
	for (i = 0; i < conf->rules.nelts; i++) {
		rc = ngx_ip_blocker_process_rule(r, &rule[i]);

		if (rc == NGX_DECLINED) {
			continue;
		}

		if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
			if (rc == NGX_OK) {
				continue;
			}

			return rc;
		}

		/* clcf->satisfy == NGX_HTTP_SATISFY_ANY */
		switch (rc) {
			case NGX_OK:
				return NGX_OK;
			case NGX_HTTP_FORBIDDEN:
			case NGX_HTTP_UNAUTHORIZED:
				out_rc = rc;
				break;
		}
	}

	return out_rc;
}

static ngx_int_t ngx_ip_blocker_process_rule(ngx_http_request_t *r, ngx_http_ip_blocker_ruleset_st *rule)
{
	ngx_http_core_loc_conf_t *clcf;
	u_char *base, *addr;
	size_t len, addr_len;
	struct sockaddr_in *sin;
#if NGX_HAVE_INET6
	struct sockaddr_in6 *sin6;
#endif /* NGX_HAVE_INET6 */
	int (*compare)(const void *a, const void *b);

	if (rule->addr == MAP_FAILED || rule->size < sizeof(ngx_ip_blocker_shm_st)) {
		return NGX_ERROR;
	}

	ngx_ip_blocker_rwlock_rlock(&rule->addr->lock);

	/* runlock is called inside of remap iff NGX_ERROR is returned */
	if (rule->revision != rule->addr->revision
		&& ngx_http_ip_blocker_remap(rule, r->connection->log) != NGX_OK) {
		return NGX_ERROR;
	}

	switch (r->connection->sockaddr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)r->connection->sockaddr;

			base = (u_char *)rule->addr + rule->addr->ip4.base;
			len = rule->addr->ip4.len;

			addr = (u_char *)&sin->sin_addr.s_addr;
			addr_len = 4;

			compare = ngx_http_ip_blocker_ip4_compare;
			break;
#if NGX_HAVE_INET6
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)r->connection->sockaddr;

			addr = sin6->sin6_addr.s6_addr;
			addr_len = 16;

			if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
				base = (u_char *)rule->addr + rule->addr->ip4.base;
				len = rule->addr->ip4.len;

				addr += 12;
				addr_len -= 12;

				compare = ngx_http_ip_blocker_ip4_compare;
			} else {
				base = (u_char *)rule->addr + rule->addr->ip6.base;
				len = rule->addr->ip6.len;

				compare = ngx_http_ip_blocker_ip6_compare;
			}

			break;
#endif /* NGX_HAVE_INET6 */
		default:
			ngx_ip_blocker_rwlock_runlock(&rule->addr->lock);
			return NGX_ERROR;
	}

search:
	if (len && bsearch(addr, base, len / addr_len, addr_len, compare)) {
		/* remote address found in block list */
		ngx_ip_blocker_rwlock_runlock(&rule->addr->lock);

		if (rule->addr->whitelist) {
			return NGX_OK;
		}

		clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
		if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"access forbidden by rule");
		}

		return NGX_HTTP_FORBIDDEN;
#if NGX_HAVE_INET6
	} else if (addr_len == 16) {
		base = (u_char *)rule->addr + rule->addr->ip6route.base;
		len = rule->addr->ip6route.len;

		addr_len = 8;

		compare = ngx_http_ip_blocker_ip6route_compare;
		goto search;
#endif /* NGX_HAVE_INET6 */
	} else {
		/* remote address not found in block list */
		ngx_ip_blocker_rwlock_runlock(&rule->addr->lock);

		clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
		if (rule->addr->whitelist && clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
			return NGX_HTTP_FORBIDDEN;
		} else {
			return NGX_DECLINED;
		}
	}
}

static int ngx_http_ip_blocker_ip4_compare(const void *a, const void *b)
{
	return memcmp(a, b, 4);
}

#if NGX_HAVE_INET6
static int ngx_http_ip_blocker_ip6_compare(const void *a, const void *b)
{
	return memcmp(a, b, 16);
}

static int ngx_http_ip_blocker_ip6route_compare(const void *a, const void *b)
{
	return memcmp(a, b, 8);
}
#endif /* NGX_HAVE_INET6 */
