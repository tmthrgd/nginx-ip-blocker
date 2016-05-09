typedef struct {
	struct {
		size_t base;
		size_t len;
	} ip4, ip6;
} ngx_ip_blocker_shm_st;
