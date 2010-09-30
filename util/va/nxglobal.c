#include "config.h"

#include "nxglobal.h"
#include "nxrdata.h"

//nx_global g_global;

void nx_global_int(struct nx_global* g)
{
	if(g == NULL)
		return;

	//nx_log_info("set nx_flag");
	g->nx_flag = 0;
	g->set = NULL;
	
	nx_log_info("create rdata set");
	g->set = nx_rdata_set_create(g->set);

	/*
	nx_log_info("set an IP");
	nx_rdata_set_add(g->set, "127.0.0.1", 1);
	nx_rdata_set_add(g->set, "192.168.0.1", 2);
	*/
	
	return;
}

