#ifndef _NXR_CONTROL_H_
#define _NXR_CONTROL_H_

struct worker;

#ifdef HAVE_OPENSSL_SSL_H
#include "openssl/ssl.h"
#endif

#define NS_COMMAND_RSIA_START   		"rsia_start"
#define NS_COMMAND_RSIA_STOP            "rsia_stop"
#define NS_COMMAND_RSIA_REPLY           "rsia_reply"
#define NS_COMMAND_RSIA_DEFAULT         "rsia_default"
#define NS_COMMAND_RSIA_ACTIVE          "rsia_active"
#define NS_COMMAND_RSIA_INACTIVE        "rsia_inactive"
#define NS_COMMAND_RSIA_SONATA          "rsia_sonata"


void do_rsia_cmd(SSL* ssl, struct worker* worker, char* arg);

int ns_server_rsia_start(SSL* ssl, char* arg);
int ns_server_rsia_stop(SSL* ssl, char* arg);
int ns_server_rsia_reply(SSL* ssl, struct worker* worker, char* arg);
int ns_server_rsia_default(SSL* ssl, struct worker* worker, char* arg);
int ns_server_rsia_active(SSL* ssl);
int ns_server_rsia_inactive(SSL* ssl);
int ns_server_rsia_sonata(SSL* ssl, struct worker* worker, char* arg);

int 
command_compare(const char* text, const char* command);

int
strcasecmp(const char *s1, const char *s2);

int
strncasecmp(const char *s1, const char *s2, unsigned int n);

char *
next_token(char **stringp, const char *delim);

char *
rs_strsep(char **stringp, const char *delim);



#endif
