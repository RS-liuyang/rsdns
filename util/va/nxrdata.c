#include "config.h"

#include "nxrdata.h"
#include "util/data/packed_rrset.h"
#include "util/log.h"

int nx_rdata_element_clear(struct nx_rdata_element* element)
{
	element->current = 0;
	element->factor = 0;
	element->sum = 0;
	element->ipaddr = 0;

	return 1;
}

int nx_rdata_element_set(struct nx_rdata_element * element,uint32_t ipaddr, int factor)
{
	nx_rdata_element_clear(element);

	element->factor = factor;
	element->ipaddr = ipaddr;

	element->p_rdata->rr_data[0][0] = 0;
	element->p_rdata->rr_data[0][1] = 4;
	memcpy(&element->p_rdata->rr_data[0][2], &ipaddr, 4);
	
	return 1;
}

struct nx_rdata_set* nx_rdata_set_create(struct nx_rdata_set* oldset)
{
	int one_rdata_size, all_rdata_size; 
	int i;
	uint8_t* p;
	struct nx_rdata_set* set;
	struct packed_rrset_data* tmp_rdata;
	size_t* tmp_rrlen;
	uint32_t* tmp_rrttl;
	uint8_t** tmp_rrdata;
	
	if(oldset != NULL)
		nx_rdata_set_destroy(oldset);

	set = (struct nx_rdata_set*)malloc(sizeof(struct nx_rdata_set));

	if(set == NULL)
		nx_log_info("set malloc failed");

	one_rdata_size = sizeof(struct packed_rrset_data) + sizeof(size_t) + sizeof(uint8_t*) + 
		sizeof(uint32_t) + NX_RDATA_LENGTH*sizeof(uint8_t);
	all_rdata_size = one_rdata_size * NX_RDATA_SET_SIZE;

	nx_log_info("rdata size is %d", all_rdata_size);
/*	
	p = (uint8_t*)malloc(all_rdata_size);

	if(p == NULL)
		nx_log_info("rdata malloc failed");
*/
	for(i = 0; i < NX_RDATA_SET_SIZE; i++)
	{
		//nx_log_info("slot point is %lu", (uint32_t)p);

		p = (uint8_t*)malloc(one_rdata_size);
		
		tmp_rdata = (struct packed_rrset_data*)p;
		tmp_rdata->count = 1;
		tmp_rdata->rrsig_count = 0;
		tmp_rdata->ttl = 3600;
		tmp_rdata->trust = 8;
		tmp_rdata->security = 2;

		
		p += sizeof(struct packed_rrset_data);
		tmp_rrlen = (size_t*)p;
		*tmp_rrlen = NX_RDATA_LENGTH;
		tmp_rdata->rr_len = tmp_rrlen;

		p += sizeof(size_t);
		tmp_rrdata = (uint8_t**)p;
		tmp_rdata->rr_data = tmp_rrdata;

		p += sizeof(uint8_t*);
		tmp_rrttl = (uint32_t*)p;
		*tmp_rrttl = 3600;
		tmp_rdata->rr_ttl = tmp_rrttl;

		p += sizeof(uint32_t);
		tmp_rdata->rr_data[0] = (uint8_t*)p;
		
		//p += sizeof(uint8_t) * NX_RDATA_LENGTH;

		set->element[i].p_rdata = tmp_rdata;
	}

	nx_rdata_set_init(set);
	
	return set;
}

int nx_rdata_set_init(struct nx_rdata_set * set)
{
	int i;
	set->current = 0;
	set->sum = 0;
	set->loadsize = 0;

	for(i = 0; i < NX_RDATA_SET_SIZE; i++)
	{
		set->loadlist[i] = i;
	}
	
	return 1;
}

int nx_rdata_set_add(struct nx_rdata_set * set,const char * szIP, int factor)
{
	uint32_t ipaddr;
	int nret;
	struct nx_rdata_element* e = NULL;
	int found = -1;
	int i = 0;

	if(set == NULL)
		nx_log_info("set is NULL");
	
	nx_log_info("loadsize is %d", set->loadsize);

	if(inet_pton(AF_INET, szIP, &ipaddr) <= 0)
	{
		nx_log_info("inet_pton error for %s", szIP);
		return 0;
	}
	
	for(i = 0; i < set->loadsize; i++)
	{
		e = &set->element[set->loadlist[i]];
		if (e->ipaddr == ipaddr)
		{
			found = i;
			break;
		}
	}

	if(found != -1)
	{
		e->factor = factor;
		return 0;
	}
	
	if(set->loadsize >= NX_RDATA_SET_SIZE)
	{
		nx_log_info("set's loadsize is %d", set->loadsize);
		return 0;
	}

	e = &set->element[set->loadlist[set->loadsize]];

	nx_rdata_element_set(e, ipaddr, factor);
	
	memset(e->szIP, 0, sizeof(e->szIP));
	strcpy(e->szIP, szIP);

	set->loadsize++;
	
	return 1;
}

const char* nx_rdata_get_status(struct nx_rdata_set * set,const char * szIP,
	int* factor, long* sum, int* cur)
{
	int i, ivalue;
	int found = -1;
	uint32_t ipaddr;
	struct nx_rdata_element *e;
	
	if(inet_pton(AF_INET, szIP, &ipaddr) == -1)
		return 0;

	for(i = 0; i < set->loadsize; i++)
	{
		e = &set->element[set->loadlist[i]];
		if (e->ipaddr == ipaddr)
		{
			found = i;
			break;
		}
	}

	if(found == -1)
		return NULL;

	*factor = e->factor;
	*sum = e->sum;
	*cur = e->current;

	return e->szIP;

}

int nx_rdata_set_del(struct nx_rdata_set * set,const char * szIP)
{
	int i, ivalue;
	int found = -1;
	uint32_t ipaddr;
	struct nx_rdata_element *e;
	
	if(inet_pton(AF_INET, szIP, &ipaddr) == -1)
		return 0;

	for(i = 0; i < set->loadsize; i++)
	{
		e = &set->element[set->loadlist[i]];
		if (e->ipaddr == ipaddr)
		{
			found = i;
			break;
		}
	}

	if(found == -1)
		return 0;

	ivalue = set->loadlist[set->loadsize - 1];
	set->loadlist[set->loadsize-1]=set->loadlist[found];
	set->loadlist[found] = ivalue;

	set->loadsize --;
	
	return 1;
}

int nx_rdata_set_clear(struct nx_rdata_set* set)
{
	int i;
	for(i = 0; i < NX_RDATA_SET_SIZE; i++)
	{
		nx_rdata_element_clear(&set->element[i]);
	}

	nx_rdata_set_init(set);
	
	return 1;
}

int nx_rdata_set_destroy(struct nx_rdata_set* set)
{
	int i;
	
	if (set == NULL)
		return 1;

	for(i = 0; i < NX_RDATA_SET_SIZE; i++)
	{
		if(set->element[i].p_rdata != NULL)
		{
			free(set->element[i].p_rdata);
			set->element[i].p_rdata = NULL;
		}
	}
	
	free(set);
	set = NULL;

	return 1;	
}

char* nx_rdata_set_getelementIP(struct nx_rdata_set* set, int n)
{
	if (n >= set->loadsize)
		return NULL;
	
	struct nx_rdata_element* e;
	e = &set->element[set->loadlist[n]];

	return e->szIP;
}

struct packed_rrset_data* get_nx_rdata(struct nx_rdata_set* set)
{
	int lastcurrent;
	struct nx_rdata_element* e;
	struct packed_rrset_data* ret = NULL;
	
	if(set == NULL)
		return NULL;
	if(set->loadsize <= 0)
		return NULL;

	lastcurrent = set->current;
	
	if(lastcurrent >= set->loadsize)
		lastcurrent = 0;

	e = &set->element[set->loadlist[lastcurrent]];
	ret = e->p_rdata;
	e->current++;
	e->sum++;

	if(e->current >= e->factor)
	{
		e->current = 0;
		set->current++;
		if(set->current >= set->loadsize)
			set->current = 0;
	}

	set->sum++;
	return ret;
	
}


void
nx_log_info(const char *format, ...)
{
	return;
    va_list args;
	va_start(args, format);
	log_vmsg(6, "info", format, args);
	va_end(args);
}
