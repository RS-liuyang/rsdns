#ifndef _NX_RDATA_H_
#define _NX_RDATA_H_

struct packed_rrset_data;

#define NX_RDATA_LENGTH 6
#define NX_RDATA_SET_SIZE 100

struct nx_rdata_element{
	int factor;
	int current;
	long sum;
	uint32_t ipaddr;
	char szIP[20];
	struct packed_rrset_data* p_rdata;
};

struct nx_rdata_set{
	long long	sum;
	int			current;

	int			loadsize;
	int			loadlist[NX_RDATA_SET_SIZE];
	struct nx_rdata_element element[NX_RDATA_SET_SIZE];
};


struct nx_rdata_set* nx_rdata_set_create(struct nx_rdata_set* set);
int nx_rdata_set_init(struct nx_rdata_set* set);
int nx_rdata_set_add(struct nx_rdata_set* set, const char* szIP, int factor);

const char* 
nx_rdata_get_status(struct nx_rdata_set * set,const char * szIP,
	int* factor, long* sum, int* cur);

int nx_rdata_set_del(struct nx_rdata_set* set, const char* szIP);
int nx_rdata_set_clear(struct nx_rdata_set* set);
int nx_rdata_set_destroy(struct nx_rdata_set* set);

char* 
nx_rdata_set_getelementIP(struct nx_rdata_set* set, int n);

struct packed_rrset_data* get_nx_rdata(struct nx_rdata_set* set);


int nx_rdata_element_clear(struct nx_rdata_element* element);
int nx_rdata_element_set(struct nx_rdata_element* element, uint32_t ipaddr, int factor);

void
nx_log_info(const char *format, ...);

#endif
