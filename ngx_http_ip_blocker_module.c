#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_ip_blocker_shm.h"

#include <fcntl.h>           // For O_* constants
#include <sys/stat.h>        // For mode constants
#include <sys/mman.h>        // For shm_*

typedef struct {
	ngx_str_t name;

	int fd;

	ngx_ip_blocker_shm_st *addr;
	size_t size;
} ngx_http_ip_blocker_srv_conf_st;

static ngx_int_t ngx_http_ip_blocker_init(ngx_conf_t *cf);

static void *ngx_http_ip_blocker_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ip_blocker_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static void ngx_http_ip_blocker_cleanup(void *data);

static ngx_int_t ngx_http_ip_blocker_access_handler(ngx_http_request_t *r);

static int ngx_http_ip_blocker_ip4_compare(const void *a, const void *b);
#if NGX_HAVE_INET6
static int ngx_http_ip_blocker_ip6_compare(const void *a, const void *b);
#endif /* NGX_HAVE_INET6 */

static ngx_command_t ngx_http_ip_blocker_module_commands[] = {
	{ ngx_string("ip_blocker"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_ip_blocker_srv_conf_st, name),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_ip_blocker_module_ctx = {
	NULL,                                /* preconfiguration */
	ngx_http_ip_blocker_init,            /* postconfiguration */

	NULL,                                /* create main configuration */
	NULL,                                /* init main configuration */

	ngx_http_ip_blocker_create_srv_conf, /* create server configuration */
	ngx_http_ip_blocker_merge_srv_conf,  /* merge server configuration */

	NULL,                                /* create location configuration */
	NULL                                 /* merge location configuration */
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

static void *ngx_http_ip_blocker_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_ip_blocker_srv_conf_st *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip_blocker_srv_conf_st));
	if (!conf) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->name = { 0, NULL };
	 *
	 *     conf->size = 0;
	 */

	conf->fd = -1;
	conf->addr = MAP_FAILED;

	return conf;
}

static char *ngx_http_ip_blocker_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	const ngx_http_ip_blocker_srv_conf_st *prev = parent;
	ngx_http_ip_blocker_srv_conf_st *conf = child;
	ngx_pool_cleanup_t *cln;
	struct stat sb;

	ngx_conf_merge_str_value(conf->name, prev->name, "");

	if (!conf->name.len) {
		return NGX_CONF_OK;
	}

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (!cln) {
		return NGX_CONF_ERROR;
	}

	cln->handler = ngx_http_ip_blocker_cleanup;
	cln->data = conf;

	conf->fd = shm_open((const char *)conf->name.data, O_RDWR, 0);
	if (conf->fd == -1) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "shm_open failed");
		return NGX_CONF_ERROR;
	}

	if (fstat(conf->fd, &sb) == -1) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "fstat failed");
		return NGX_CONF_ERROR;
	}

	conf->addr = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, conf->fd, 0);
	if (conf->addr == MAP_FAILED) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "mmap failed");
		return NGX_CONF_ERROR;
	}

	conf->size = sb.st_size;

	if (conf->size < sizeof(ngx_ip_blocker_shm_st)
		|| conf->size < sizeof(ngx_ip_blocker_shm_st) + conf->addr->ip4.len + conf->addr->ip6.len
		|| (conf->addr->ip4.len && conf->addr->ip4.base < sizeof(ngx_ip_blocker_shm_st))
		|| (conf->addr->ip6.len && conf->addr->ip6.base < sizeof(ngx_ip_blocker_shm_st))
		|| conf->addr->ip4.base + conf->addr->ip4.len > conf->size
		|| conf->addr->ip6.base + conf->addr->ip6.len > conf->size) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "shared memmory is invalid");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static void ngx_http_ip_blocker_cleanup(void *data)
{
	ngx_http_ip_blocker_srv_conf_st *conf = data;

	if (conf->addr != MAP_FAILED) {
		munmap(conf->addr, conf->size);
	}

	if (conf->fd != -1) {
		close(conf->fd);
	}
}

static ngx_int_t ngx_http_ip_blocker_access_handler(ngx_http_request_t *r)
{
	ngx_http_ip_blocker_srv_conf_st *conf;
	ngx_http_core_loc_conf_t *clcf;
	u_char *base, *addr;
	size_t len, addr_len;
	struct sockaddr_in *sin;
#if NGX_HAVE_INET6
	struct sockaddr_in6 *sin6;
#endif /* NGX_HAVE_INET6 */
	int (*compare)(const void *a, const void *b);

	conf = ngx_http_get_module_srv_conf(r, ngx_http_ip_blocker_module);
	if (!conf || !conf->name.len) {
		return NGX_DECLINED;
	}

	switch (r->connection->sockaddr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)r->connection->sockaddr;

			base = (u_char *)conf->addr + conf->addr->ip4.base;
			len = conf->addr->ip4.len;

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
				base = (u_char *)conf->addr + conf->addr->ip4.base;
				len = conf->addr->ip4.len;

				addr += 12;
				addr_len -= 12;

				compare = ngx_http_ip_blocker_ip4_compare;
			} else {
				base = (u_char *)conf->addr + conf->addr->ip6.base;
				len = conf->addr->ip6.len;

				compare = ngx_http_ip_blocker_ip6_compare;
			}

			break;
#endif /* NGX_HAVE_INET6 */
		default:
			return NGX_DECLINED;
	}

	if (!len || !bsearch(addr, base, len / addr_len, addr_len, compare)) {
		/* remote address not found in block list */
		return NGX_DECLINED;
	}

	/* remote address found in block list */
	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by rule");
	}

	return NGX_HTTP_FORBIDDEN;
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
#endif /* NGX_HAVE_INET6 */
