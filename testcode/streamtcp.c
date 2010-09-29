/*
 * testcode/streamtcp.c - debug program perform multiple DNS queries on tcp.
 *
 * Copyright (c) 2008, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * This program performs multiple DNS queries on a TCP stream.
 */

#include "config.h"
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include "ldns/ldns.h"
#include <signal.h>
#include "util/locks.h"
#include "util/log.h"
#include "util/net_help.h"
#include "util/data/msgencode.h"
#include "util/data/msgreply.h"
#include "util/data/dname.h"

#ifndef PF_INET6
/** define in case streamtcp is compiled on legacy systems */
#define PF_INET6 10
#endif

/** usage information for streamtcp */
static void usage(char* argv[])
{
	printf("usage: %s [options] name type class ...\n", argv[0]);
	printf("	sends the name-type-class queries over TCP.\n");
	printf("-f server	what ipaddr@portnr to send the queries to\n");
	printf("-u 		use UDP. No retries are attempted.\n");
	printf("-n 		do not wait for an answer.\n");
	printf("-h 		this help text\n");
	exit(1);
}

/** open TCP socket to svr */
static int
open_svr(const char* svr, int udp)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int fd = -1;
	/* svr can be ip@port */
	memset(&addr, 0, sizeof(addr));
	if(!extstrtoaddr(svr, &addr, &addrlen)) {
		printf("fatal: bad server specs '%s'\n", svr);
		exit(1);
	}
	fd = socket(addr_is_ip6(&addr, addrlen)?PF_INET6:PF_INET,
		udp?SOCK_DGRAM:SOCK_STREAM, 0);
	if(fd == -1) {
#ifndef USE_WINSOCK
		perror("socket() error");
#else
		printf("socket: %s\n", wsa_strerror(WSAGetLastError()));
#endif
		exit(1);
	}
	if(connect(fd, (struct sockaddr*)&addr, addrlen) < 0) {
#ifndef USE_WINSOCK
		perror("connect() error");
#else
		printf("connect: %s\n", wsa_strerror(WSAGetLastError()));
#endif
		exit(1);
	}
	return fd;
}

/** write a query over the TCP fd */
static void
write_q(int fd, int udp, ldns_buffer* buf, int id, 
	const char* strname, const char* strtype, const char* strclass)
{
	struct query_info qinfo;
	ldns_rdf* rdf;
	uint16_t len;
	/* qname */
	rdf = ldns_dname_new_frm_str(strname);
	if(!rdf) {
		printf("cannot parse query name: '%s'\n", strname);
		exit(1);
	}
	qinfo.qname = memdup(ldns_rdf_data(rdf), ldns_rdf_size(rdf));
	(void)dname_count_size_labels(qinfo.qname, &qinfo.qname_len);
	ldns_rdf_deep_free(rdf);
	if(!qinfo.qname) fatal_exit("out of memory");

	/* qtype and qclass */
	qinfo.qtype = ldns_get_rr_type_by_name(strtype);
	qinfo.qclass = ldns_get_rr_class_by_name(strclass);

	/* make query */
	qinfo_query_encode(buf, &qinfo);
	ldns_buffer_write_u16_at(buf, 0, (uint16_t)id);
	ldns_buffer_write_u16_at(buf, 2, BIT_RD);

	/* send it */
	if(!udp) {
		len = (uint16_t)ldns_buffer_limit(buf);
		len = htons(len);
		if(send(fd, (void*)&len, sizeof(len), 0)<(ssize_t)sizeof(len)){
#ifndef USE_WINSOCK
			perror("send() len failed");
#else
			printf("send len: %s\n", 
				wsa_strerror(WSAGetLastError()));
#endif
			exit(1);
		}
	}
	if(send(fd, (void*)ldns_buffer_begin(buf), ldns_buffer_limit(buf), 0) < 
		(ssize_t)ldns_buffer_limit(buf)) {
#ifndef USE_WINSOCK
		perror("send() data failed");
#else
		printf("send data: %s\n", wsa_strerror(WSAGetLastError()));
#endif
		exit(1);
	}

	free(qinfo.qname);
}

/** receive DNS datagram over TCP and print it */
static void
recv_one(int fd, int udp, ldns_buffer* buf)
{
	uint16_t len;
	ldns_pkt* pkt;
	ldns_status status;
	if(!udp) {
		if(recv(fd, (void*)&len, sizeof(len), 0)<(ssize_t)sizeof(len)){
#ifndef USE_WINSOCK
			perror("read() len failed");
#else
			printf("read len: %s\n", 
				wsa_strerror(WSAGetLastError()));
#endif
			exit(1);
		}
		len = ntohs(len);
		ldns_buffer_clear(buf);
		ldns_buffer_set_limit(buf, len);
		if(recv(fd, (void*)ldns_buffer_begin(buf), len, 0) < 
			(ssize_t)len) {
#ifndef USE_WINSOCK
			perror("read() data failed");
#else
			printf("read data: %s\n", 
				wsa_strerror(WSAGetLastError()));
#endif
			exit(1);
		}
	} else {
		ssize_t l;
		ldns_buffer_clear(buf);
		if((l=recv(fd, (void*)ldns_buffer_begin(buf), 
			ldns_buffer_capacity(buf), 0)) < 0) {
#ifndef USE_WINSOCK
			perror("read() data failed");
#else
			printf("read data: %s\n", 
				wsa_strerror(WSAGetLastError()));
#endif
			exit(1);
		}
		ldns_buffer_set_limit(buf, (size_t)l);
		len = (size_t)l;
	}
	printf("\nnext received packet\n");
	log_buf(0, "data", buf);

	status = ldns_wire2pkt(&pkt, ldns_buffer_begin(buf), len);
	if(status != LDNS_STATUS_OK) {
		printf("could not parse incoming packet: %s\n",
			ldns_get_errorstr_by_id(status));
		log_buf(0, "data was", buf);
		exit(1);
	}
	ldns_pkt_print(stdout, pkt);
	ldns_pkt_free(pkt);
}

/** send the TCP queries and print answers */
static void
send_em(const char* svr, int udp, int noanswer, int num, char** qs)
{
	ldns_buffer* buf = ldns_buffer_new(65553);
	int fd = open_svr(svr, udp);
	int i;
	if(!buf) fatal_exit("out of memory");
	for(i=0; i<num; i+=3) {
		printf("\nNext query is %s %s %s\n", qs[i], qs[i+1], qs[i+2]);
		write_q(fd, udp, buf, i, qs[i], qs[i+1], qs[i+2]);
		/* print at least one result */
		if(!noanswer)
			recv_one(fd, udp, buf);
	}

#ifndef USE_WINSOCK
	close(fd);
#else
	closesocket(fd);
#endif
	ldns_buffer_free(buf);
	printf("orderly exit\n");
}

#ifdef SIGPIPE
/** SIGPIPE handler */
static RETSIGTYPE sigh(int sig)
{
	if(sig == SIGPIPE) {
		printf("got SIGPIPE, remote connection gone\n");
		exit(1);
	}
	printf("Got unhandled signal %d\n", sig);
	exit(1);
}
#endif /* SIGPIPE */

/** getopt global, in case header files fail to declare it. */
extern int optind;
/** getopt global, in case header files fail to declare it. */
extern char* optarg;

/** main program for streamtcp */
int main(int argc, char** argv) 
{
	int c;
	const char* svr = "127.0.0.1";
	int udp = 0;
	int noanswer = 0;

#ifdef USE_WINSOCK
	WSADATA wsa_data;
	if(WSAStartup(MAKEWORD(2,2), &wsa_data) != 0) {
		printf("WSAStartup failed\n");
		return 1;
	}
#endif

	/* lock debug start (if any) */
	log_init(0, 0, 0);
	checklock_start();

#ifdef SIGPIPE
	if(signal(SIGPIPE, &sigh) == SIG_ERR) {
		perror("could not install signal handler");
		return 1;
	}
#endif

	/* command line options */
	if(argc == 1) {
		usage(argv);
	}
	while( (c=getopt(argc, argv, "f:hnu")) != -1) {
		switch(c) {
			case 'f':
				svr = optarg;
				break;
			case 'n':
				noanswer = 1;
				break;
			case 'u':
				udp = 1;
				break;
			case 'h':
			case '?':
			default:
				usage(argv);
		}
	}
	argc -= optind;
	argv += optind;

	if(argc % 3 != 0) {
		printf("queries must be multiples of name,type,class\n");
		return 1;
	}
	send_em(svr, udp, noanswer, argc, argv);
	checklock_stop();
#ifdef USE_WINSOCK
	WSACleanup();
#endif
	return 0;
}
