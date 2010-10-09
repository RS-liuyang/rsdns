#ifndef _NX_GLOBAL_H_
#define _NX_GLOBAL_H_

struct nx_rdata_set;

struct nx_global
{
	int nx_flag;
	struct nx_rdata_set* set;
};

void nx_global_int(struct nx_global* g);

#ifndef RS_MAIN
struct nx_global g_nx;
#endif

#endif
