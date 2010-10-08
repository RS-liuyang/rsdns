
#include "config.h"
#include "util/va/nxrcontrol.h"
#include "util/va/nxrdata.h"
#include "util/va/nxglobal.h"
#include "util/log.h"

#ifdef HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif

static const unsigned char charmap[] = {
	0000, 0001, 0002, 0003, 0004, 0005, 0006, 0007,
	0010, 0011, 0012, 0013, 0014, 0015, 0016, 0017,
	0020, 0021, 0022, 0023, 0024, 0025, 0026, 0027,
	0030, 0031, 0032, 0033, 0034, 0035, 0036, 0037,
	0040, 0041, 0042, 0043, 0044, 0045, 0046, 0047,
	0050, 0051, 0052, 0053, 0054, 0055, 0056, 0057,
	0060, 0061, 0062, 0063, 0064, 0065, 0066, 0067,
	0070, 0071, 0072, 0073, 0074, 0075, 0076, 0077,
	0100, 0141, 0142, 0143, 0144, 0145, 0146, 0147,
	0150, 0151, 0152, 0153, 0154, 0155, 0156, 0157,
	0160, 0161, 0162, 0163, 0164, 0165, 0166, 0167,
	0170, 0171, 0172, 0133, 0134, 0135, 0136, 0137,
	0140, 0141, 0142, 0143, 0144, 0145, 0146, 0147,
	0150, 0151, 0152, 0153, 0154, 0155, 0156, 0157,
	0160, 0161, 0162, 0163, 0164, 0165, 0166, 0167,
	0170, 0171, 0172, 0173, 0174, 0175, 0176, 0177,
	0200, 0201, 0202, 0203, 0204, 0205, 0206, 0207,
	0210, 0211, 0212, 0213, 0214, 0215, 0216, 0217,
	0220, 0221, 0222, 0223, 0224, 0225, 0226, 0227,
	0230, 0231, 0232, 0233, 0234, 0235, 0236, 0237,
	0240, 0241, 0242, 0243, 0244, 0245, 0246, 0247,
	0250, 0251, 0252, 0253, 0254, 0255, 0256, 0257,
	0260, 0261, 0262, 0263, 0264, 0265, 0266, 0267,
	0270, 0271, 0272, 0273, 0274, 0275, 0276, 0277,
	0300, 0301, 0302, 0303, 0304, 0305, 0306, 0307,
	0310, 0311, 0312, 0313, 0314, 0315, 0316, 0317,
	0320, 0321, 0322, 0323, 0324, 0325, 0326, 0327,
	0330, 0331, 0332, 0333, 0334, 0335, 0336, 0337,
	0340, 0341, 0342, 0343, 0344, 0345, 0346, 0347,
	0350, 0351, 0352, 0353, 0354, 0355, 0356, 0357,
	0360, 0361, 0362, 0363, 0364, 0365, 0366, 0367,
	0370, 0371, 0372, 0373, 0374, 0375, 0376, 0377
};

extern struct nx_global g_nx;

static void
log_crypto_err(const char* str)
{
	/* error:[error code]:[library name]:[function name]:[reason string] */
	char buf[128];
	unsigned long e;
	ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
	log_err("%s crypto %s", str, buf);
	while( (e=ERR_get_error()) ) {
		ERR_error_string_n(e, buf, sizeof(buf));
		log_err("and additionally crypto %s", buf);
	}
}

static int
ssl_print_text(SSL* ssl, const char* text)
{
	int r;
	ERR_clear_error();
	if((r=SSL_write(ssl, text, (int)strlen(text))) <= 0) {
		if(SSL_get_error(ssl, r) == SSL_ERROR_ZERO_RETURN) {
			verbose(VERB_QUERY, "warning, in SSL_write, peer "
				"closed connection");
			return 0;
		}
		log_crypto_err("could not SSL_write");
		return 0;
	}
	return 1;
}


static int
ssl_print_vmsg(SSL* ssl, const char* format, va_list args)
{
	char msg[1024];
	vsnprintf(msg, sizeof(msg), format, args);
	return ssl_print_text(ssl, msg);
}

/** printf style printing to the ssl connection */
static int ssl_printf(SSL* ssl, const char* format, ...)
{
	va_list args;
	int ret;
	va_start(args, format);
	ret = ssl_print_vmsg(ssl, format, args);
	va_end(args);
	return ret;
}


void do_rsia_cmd(SSL* ssl, struct worker* worker, char* arg)
{
	int result;
	if(command_compare(arg, NS_COMMAND_RSIA_START)){
		result = ns_server_rsia_start(ssl, arg);
	}else if(command_compare(arg,NS_COMMAND_RSIA_STOP)){
		result = ns_server_rsia_stop(ssl, arg);
	}else if(command_compare(arg,NS_COMMAND_RSIA_REPLY)){
		result = ns_server_rsia_reply(ssl, worker, arg);
	}else if(command_compare(arg,NS_COMMAND_RSIA_DEFAULT)){
		result = ns_server_rsia_default(ssl, worker, arg);
	}else if(command_compare(arg,NS_COMMAND_RSIA_ACTIVE)){
		result = ns_server_rsia_active(ssl);
	}else if(command_compare(arg,NS_COMMAND_RSIA_INACTIVE)){
		result = ns_server_rsia_inactive(ssl);
	}else if(command_compare(arg,NS_COMMAND_RSIA_SONATA)){
		result = ns_server_rsia_sonata(ssl, worker, arg);
	}

	/*just for debug
	if(result <= 0)
		(void)ssl_printf(ssl, "failed\n");
	else
		(void)ssl_printf(ssl, "successed\n");
	*/
	
}

int ns_server_rsia_start(SSL* ssl, char* arg)
{
	char* ptr, *p_ipaddr;
	char* input = arg;
	int factor;
	int result = 1;
	
	ptr = next_token(&input, " \t");
	if(ptr == NULL)
		return -1;
	
	p_ipaddr = next_token(&input, " \t");
	if(ptr == NULL)
		return -1;

	factor = atoi(input);
	if(factor <= 0)
		factor = 1;
		
	if(!nx_rdata_set_add(g_nx.set, p_ipaddr, factor))
		result = -1;

	(void)ssl_printf(ssl, "rsia_start\n");
	return result;

}

int ns_server_rsia_stop(SSL* ssl, char* arg)
{
	char* ptr, *p_ipaddr;
	char* input = arg;
	int result = 1;
	
	ptr = next_token(&input, " \t");
	if(ptr == NULL)
		return -1;
	
	p_ipaddr = next_token(&input, " \t");
	if(ptr == NULL)
		return -1;

	if(!nx_rdata_set_del(g_nx.set, p_ipaddr))
		result = -1;

	(void)ssl_printf(ssl, "rsia_stop\n");
	return result;	

}

int ns_server_rsia_reply(SSL* ssl, struct worker* worker, char* arg)
{
	int i;
	char* szIP;

	for(i=0;; i++)
	{
		szIP = nx_rdata_set_getelementIP(g_nx.set, i);
		if(szIP == NULL)
			break;
		(void)ssl_printf(ssl, "%s\n", szIP);
	}
	return 1;
}

int ns_server_rsia_default(SSL* ssl, struct worker* worker, char* arg)
{
	(void)ssl_printf(ssl, "rsia_default not supported!\n");
	return 1;

}

int ns_server_rsia_active(SSL* ssl)
{
	g_nx.nx_flag = 1;
	(void)ssl_printf(ssl, "rsia_active\n");
	return 1;
}

int ns_server_rsia_inactive(SSL* ssl)
{
	g_nx.nx_flag = 0;
	(void)ssl_printf(ssl, "rsia_inactive\n");
	return 1;
}

int ns_server_rsia_sonata(SSL* ssl, struct worker* worker, char* arg)
{
	char* ptr, *p_ipaddr;
	char* input = arg;
	int result = 1;
	int factor, curcount;
	long sum;
	
	ptr = next_token(&input, " \t");
	if(ptr == NULL)
		return -1;
	
	p_ipaddr = next_token(&input, " \t");
	if(ptr == NULL)
		return -1;

	if(!nx_rdata_get_status(g_nx.set, p_ipaddr, &factor, &sum, 
			&curcount))
		return -1;

	(void)ssl_printf(ssl, "%s\n", p_ipaddr);
	(void)ssl_printf(ssl, "%d\n", curcount);
	(void)ssl_printf(ssl, "%li\n", sum);
	(void)ssl_printf(ssl, "%d\n", factor);

	return result;	

}

int command_compare(const char* text, const char* command)
{
	unsigned int commandlen = strlen(command);
	if (strncasecmp(text, command, commandlen) == 0 &&
	    (text[commandlen] == '\0' ||
	     text[commandlen] == ' ' ||
	     text[commandlen] == '\t'))
		return (1);
	return (0);	
}

/*
int
strcasecmp(const char *s1, const char *s2) {
	const unsigned char *cm = charmap,
		     *us1 = (const unsigned char *)s1,
		     *us2 = (const unsigned char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return (0);
	return (cm[*us1] - cm[*--us2]);
}

int
strncasecmp(const char *s1, const char *s2, unsigned int n) {
	if (n != 0) {
		const unsigned char *cm = charmap,
			     *us1 = (const unsigned char *)s1,
			     *us2 = (const unsigned char *)s2;

		do {
			if (cm[*us1] != cm[*us2++])
				return (cm[*us1] - cm[*--us2]);
			if (*us1++ == '\0')
				break;
		} while (--n != 0);
	}
	return (0);
}

*/

char *
next_token(char **stringp, const char *delim) {
	char *res;

	do {
		res = rs_strsep(stringp, delim);
		if (res == NULL)
			break;
	} while (*res == '\0');
	return (res);
}



/*%
 * Get next token from string *stringp, where tokens are possibly-empty
 * strings separated by characters from delim.  
 *
 * Writes NULs into the string at *stringp to end tokens.
 * delim need not remain constant from call to call.
 * On return, *stringp points past the last NUL written (if there might
 * be further tokens), or is NULL (if there are definitely no more tokens).
 *
 * If *stringp is NULL, strsep returns NULL.
 */
char *
rs_strsep(char **stringp, const char *delim) {
	char *s;
	const char *spanp;
	int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);
	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}

