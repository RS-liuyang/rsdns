
#include "config.h"
#include "ldns/ldns.h"
#include "util/va/nxredirect.h"
#include "util/va/nxglobal.h"
#include "util/va/nxrdata.h"

#include "util/net_help.h"
#include "util/log.h"
#include "util/data/msgreply.h"
#include "util/regional.h"
#include "util/data/packed_rrset.h"

extern struct nx_global g_nx;

struct packed_rrset_data* create_fake_answer_section(struct regional* region)
{
	struct packed_rrset_data* pd = NULL;
	
	pd = (struct packed_rrset_data*)regional_alloc_zero(region,
		sizeof(*pd));
	if(!pd)
	{
		log_err("out of memory");
		return NULL;
	}		

	pd->rr_len = (size_t*)regional_alloc(region, sizeof(size_t));
	pd->rr_ttl = (uint32_t*)regional_alloc(region, sizeof(uint32_t));
	pd->rr_data = (uint8_t**)regional_alloc(region, sizeof(uint8_t*));

	pd->count = 1;
	pd->rrsig_count = 0;
	pd->ttl = 3600; // + timenow;

	pd->trust = 8;
	pd->security = 2;

	pd->rr_len[0] = 6;
	pd->rr_ttl[0] = 3600; // + timenow;
	pd->rr_data[0] = (uint8_t*)regional_alloc(region, 6*sizeof(uint8_t));

	pd->rr_data[0][0] = 0;
	pd->rr_data[0][1] = 4;

	inet_pton(AF_INET, "192.168.1.11" , &pd->rr_data[0][2]);

	return pd;

}

struct packed_rrset_data* rrset_data_copy(struct regional* region, struct packed_rrset_data* ori)
{
	int one_rdata_size = sizeof(struct packed_rrset_data) + sizeof(size_t) + sizeof(uint8_t*) + 
		sizeof(uint32_t) + NX_RDATA_LENGTH*sizeof(uint8_t);

	struct packed_rrset_data* pd = NULL;

	pd = (struct packed_rrset_data*)regional_alloc_init(region, ori, one_rdata_size);

	packed_rrset_ptr_fixup(pd);

	return pd;

}


int nx_add_answer_reply(struct query_info* qinf, struct reply_info* rep, 
		struct regional* region, uint32_t timenow)
{
	struct ub_packed_rrset_key** oldsets = rep->rrsets;
	struct ub_packed_rrset_key** newsets = NULL;
	struct ub_packed_rrset_key* akey = NULL;
	struct packed_rrset_data* pd = NULL;

	akey = (struct ub_packed_rrset_key*)regional_alloc(region, 
		sizeof(struct ub_packed_rrset_key));
	if(!akey)
		return 0;

	akey->rk.type = htons(LDNS_RR_TYPE_A);
	akey->rk.rrset_class = htons(1);
	akey->rk.flags = 0;
	akey->rk.dname = regional_alloc_init(region, qinf->qname, qinf->qname_len);
	if(!akey->rk.dname)
		return 0;
	akey->rk.dname_len = qinf->qname_len;

	memset(&akey->entry, 0, sizeof(akey->entry));

	akey->entry.key = akey;
	akey->entry.hash = rrset_key_hash(&akey->rk);


	//pd = create_fake_answer_section(region);

	//pd = get_nx_rdata(g_nx.set);
	pd = rrset_data_copy(region, get_nx_rdata(g_nx.set));

	if(!pd)
		return 0;

	pd->ttl += timenow;
	pd->rr_ttl[0] += timenow;
	
	akey->entry.data = (void*)pd;

	newsets = (struct ub_packed_rrset_key**)regional_alloc_zero(
		region, sizeof(struct ub_packed_rrset_key*)*(rep->rrset_count + 1));

	newsets[0] = akey;
	memcpy(&newsets[1], oldsets, sizeof(struct ub_packed_rrset_key*)*rep->rrset_count);

	rep->rrsets = newsets;
	rep->rrset_count++;
	rep->an_numrrsets++;

	//free(oldsets);
	return 1;

}

int nx_mod_answer_reply(struct query_info* qinf, struct reply_info* rep, 
		struct regional* region, uint32_t timenow)
{
	struct ub_packed_rrset_key** oldsets = rep->rrsets;
	struct ub_packed_rrset_key** newsets = NULL;
	struct ub_packed_rrset_key* akey = NULL;
	struct packed_rrset_data* pd = NULL;
	int new_rrset_count;

	akey = (struct ub_packed_rrset_key*)regional_alloc(region, 
		sizeof(struct ub_packed_rrset_key));
	if(!akey)
		return 0;

	akey->rk.type = htons(LDNS_RR_TYPE_A);
	akey->rk.rrset_class = htons(1);
	akey->rk.flags = 0;
	akey->rk.dname = regional_alloc_init(region, qinf->qname, qinf->qname_len);
	if(!akey->rk.dname)
		return 0;
	akey->rk.dname_len = qinf->qname_len;

	memset(&akey->entry, 0, sizeof(akey->entry));

	akey->entry.key = akey;
	akey->entry.hash = rrset_key_hash(&akey->rk);


	//pd = create_fake_answer_section(region);

	//pd = get_nx_rdata(g_nx.set);
	pd = rrset_data_copy(region, get_nx_rdata(g_nx.set));

	
	if(!pd)
		return 0;

	pd->ttl += timenow;
	pd->rr_ttl[0] += timenow;

	akey->entry.data = (void*)pd;

	new_rrset_count = rep->rrset_count - rep->an_numrrsets + 1;

	newsets = (struct ub_packed_rrset_key**)regional_alloc_zero(
		region, sizeof(struct ub_packed_rrset_key*) * new_rrset_count);

	newsets[0] = akey;
	memcpy(&newsets[1], &oldsets[rep->an_numrrsets], sizeof(struct ub_packed_rrset_key*)*(new_rrset_count-1));

	rep->rrsets = newsets;
	rep->rrset_count = new_rrset_count;
	rep->an_numrrsets = 1;

	//free(oldsets);
	return 1;

}


int nx_redirect_log_reply(struct query_info* qinf, struct reply_info* rep,
	uint16_t flags)
{
	
	struct ub_packed_rrset_key** oldsets = rep->rrsets;
	struct ub_packed_rrset_key** newsets = NULL;
	struct ub_packed_rrset_key* akey = NULL;
	struct packed_rrset_data* pd = NULL;

	log_info("rrsets count is %d, answer number is %d", rep->rrset_count, rep->an_numrrsets);


	log_info("question type is %d, rcode is %d", qinf->qtype, FLAGS_GET_RCODE(flags));
	
	log_info("response has rrsets: %d, answer section: %d", rep->rrset_count, rep->an_numrrsets);
	
	akey = oldsets[0];
	
	log_info("rr's type is: %d, class is: %d", ntohs(akey->rk.type), ntohs(akey->rk.rrset_class));
	
	unsigned char tmp[1024];
	memset(tmp, 0, 1024);
	strncpy(tmp, akey->rk.dname, akey->rk.dname_len);
	
	log_info("rr's dname is %s, length is %d", tmp, akey->rk.dname_len);
	
	memset(tmp, 0, 1024);
	strncpy(tmp,  qinf->qname, qinf->qname_len);
	
	log_info("query's dname is %s, length is %d", tmp, qinf->qname_len);
	
	pd = (struct packed_rrset_data*)akey->entry.data;
	
	log_info("answer data -- ttl:%d, count:%d, rrsig_count: %d,\
		trust:%d, security:%d", pd->ttl, pd->count, pd->rrsig_count,
		pd->trust, pd->security);
	
	
	log_info("answer data -- rrlen:%d, rrttl:%d", pd->rr_len[0], pd->rr_ttl[0]);
	
	memset(tmp, 0,1024);
	int i;
	
	for(i=0; i<pd->rr_len[0]; i++)
		log_info("data %d is %d", i, pd->rr_data[0][i]);
	
	//strncpy(tmp, pd->rr_data[0]+2, pd->rr_len[0]-2);
//	inet_ntop(AF_INET, pd->rr_data[0]+2, tmp, pd->rr_len[0]-2);
//	log_info("answer data is: %s", tmp);

/*	
	memset(tmp, 0,1024);
	inet_pton(AF_INET, "199.181.132.250", tmp);
	
	for(i=0; i<6; i++)
		log_info("inet data %d is %d", i, (uint8_t*)tmp[i]);
*/	
	
	//ldns_rdf* t = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "199.181.132.250");
	
	//log_info("199.181.132.250 's inet is : %s", tmp);
	
	return 1;
	
}

int nx_redirect_reply_info(struct query_info* qinf, struct reply_info* rep,
	uint16_t* flags, struct regional* region, uint32_t timenow)
{	

	if((FLAGS_GET_RCODE(*flags) == LDNS_RCODE_NXDOMAIN) && (qinf->qtype == LDNS_RR_TYPE_A))
	{
		//log_info("NXDOMAIN reply");
		//log_info("question for A");
		/* no answer section */
		if(rep->an_numrrsets == 0)
		{
			if(!g_nx.nx_flag)
				return 1;
			FLAGS_SET_RCODE(*flags, LDNS_RCODE_NOERROR);
			nx_add_answer_reply(qinf, rep, region, timenow);
		}
		else
		{
			if(!g_nx.nx_flag)
				return 1;
			FLAGS_SET_RCODE(*flags, LDNS_RCODE_NOERROR);
			nx_mod_answer_reply(qinf, rep, region, timenow);

		}
			
	}
	else
	{
		//log_info("not a nxdomain reply");
		return 1;
	}

	nx_redirect_log_reply(qinf, rep, *flags);
	
	return 1;
}

int nx_reply(struct query_info* qinf, uint16_t flags)
{
	if((FLAGS_GET_RCODE(flags) == LDNS_RCODE_NXDOMAIN) && 
		(qinf->qtype == LDNS_RR_TYPE_A) &&
		g_nx.nx_flag)
	{
		//log_info("NXDOMAIN reply");
		//log_info("question for A");
		return 1;			
	}
	return 0;
}

struct ub_packed_rrset_key*
get_nx_rrset_key(struct query_info* qinfo, struct regional* region,
		uint32_t timenow)
{
	struct ub_packed_rrset_key* akey = NULL;
	struct packed_rrset_data* pd = NULL;

	akey = (struct ub_packed_rrset_key*)regional_alloc(region, 
		sizeof(struct ub_packed_rrset_key));
	if(!akey)
		return 0;

	akey->rk.type = htons(LDNS_RR_TYPE_A);
	akey->rk.rrset_class = htons(1);
	akey->rk.flags = 0;
	akey->rk.dname = qinfo->qname;
	akey->rk.dname_len = qinfo->qname_len;

	memset(&akey->entry, 0, sizeof(akey->entry));

	akey->entry.key = akey;
	akey->entry.hash = rrset_key_hash(&akey->rk);

	pd = get_nx_rdata(g_nx.set);

	if(!pd)
		return NULL;

	pd->ttl = timenow + 3600;
	pd->rr_ttl[0] = timenow + 3600;
	
	akey->entry.data = (void*)pd;

	return akey;
}


