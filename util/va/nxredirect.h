#ifndef _UTIL_VA_REDIRECT_H_
#define _UTIL_VA_REDIRECT_H_

struct query_info;
struct reply_info;
struct regional;

int nx_redirect_reply_info(struct query_info* qinf, struct reply_info* rep,
		uint16_t* flags, struct regional* region, uint32_t timenow);

int nx_reply(struct query_info* qinf, uint16_t flags);

struct ub_packed_rrset_key*
get_nx_rrset_key(struct query_info* qinfo, struct regional* region,
		uint32_t timenow);

#endif
