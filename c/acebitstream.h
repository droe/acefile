/*
 * acefile - read/test/extract ACE 1.0 and 2.0 archives in pure python
 * Copyright (C) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * NOTE:  The ACE archive format and ACE compression and decompression
 * algorithms have been designed by Marcel Lemke.  The above copyright
 * notice and license does not constitute a claim of intellectual property
 * over ACE technology beyond the copyright of this python implementation.
 */

/*
 * Fast implementation of a bit stream in c, without any python dependency.
 */

#ifndef ACEBITSTREAM_H
#define ACEBITSTREAM_H

#define ACEBITSTREAM_EOF	0xFFFFFFFF

typedef size_t (*acebitstream_read_cb_t)(void *, char *, size_t);

typedef struct acebitstream_ctx {
	acebitstream_read_cb_t read;
	void *read_ctx;

	uint64_t bits;
	size_t bitcount;

	size_t bufsz;
	uint32_t *buf;
	uint32_t *bufend;
	uint32_t *bufptr;
} acebitstream_ctx_t;

acebitstream_ctx_t * acebitstream_new(acebitstream_read_cb_t, void *, size_t);
void acebitstream_free(acebitstream_ctx_t *);
uint32_t acebitstream_skip_bits(acebitstream_ctx_t *, size_t);
uint32_t acebitstream_peek_bits(acebitstream_ctx_t *, size_t);
uint32_t acebitstream_read_bits(acebitstream_ctx_t *, size_t);

#endif

