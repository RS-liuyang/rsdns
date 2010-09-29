/*
 * testcode/readhex.c - read hex data.
 *
 * Copyright (c) 2007, NLnet Labs. All rights reserved.
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
 *
 */
/**
 * \file
 * Declarations useful for the unit tests.
 */
#include "config.h"
#include <ctype.h>
#include "testcode/readhex.h"
#include "util/log.h"

/** skip whitespace */
static void
skip_whites(const char** p)
{
	while(1) {
		while(isspace((int)**p))
			(*p)++;
		if(**p == ';') {
			/* comment, skip until newline */
			while(**p && **p != '\n')
				(*p)++;
			if(**p == '\n')
				(*p)++;
		} else return;
	}
}

/* takes a hex string and puts into buffer */
void hex_to_buf(ldns_buffer* pkt, const char* hex)
{
	const char* p = hex;
	int val;
	ldns_buffer_clear(pkt);
	while(*p) {
		skip_whites(&p);
		if(ldns_buffer_position(pkt) == ldns_buffer_limit(pkt))
			fatal_exit("hex_to_buf: buffer too small");
		if(!isalnum((int)*p))
			break;
		val = ldns_hexdigit_to_int(*p++) << 4;
		skip_whites(&p);
		log_assert(*p && isalnum((int)*p));
		val |= ldns_hexdigit_to_int(*p++);
		ldns_buffer_write_u8(pkt, (uint8_t)val);
		skip_whites(&p);
	}
	ldns_buffer_flip(pkt);
}

