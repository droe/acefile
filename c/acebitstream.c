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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "acebitstream.h"

static void
acebitstream_refill_buf(acebitstream_ctx_t *ctx)
{
	size_t n;

	assert(ctx->bufptr == ctx->bufend);
	n = ctx->read(ctx->read_ctx, (char *)ctx->buf, ctx->bufsz);
	assert(n % 4 == 0);
	if (n < ctx->bufsz) {
		ctx->bufend = ctx->buf + (n / sizeof(uint32_t));
	}

	ctx->bufptr = ctx->buf;
}

static void
acebitstream_refill_bits(acebitstream_ctx_t *ctx)
{
	assert(ctx->bitcount <= 32);
	if (ctx->bufptr == ctx->bufend) {
		acebitstream_refill_buf(ctx);
		if (ctx->bufptr == ctx->bufend)
			return;
	}
	ctx->bits |= ((uint64_t)*ctx->bufptr) << (32 - ctx->bitcount);
	ctx->bitcount += 32;
	ctx->bufptr++;
}

acebitstream_ctx_t *
acebitstream_new(acebitstream_read_cb_t read, void *read_ctx, size_t bufsz)
{
	acebitstream_ctx_t *ctx;

	ctx = malloc(sizeof(acebitstream_ctx_t));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(acebitstream_ctx_t));

	ctx->read = read;
	ctx->read_ctx = read_ctx;

	ctx->buf = malloc(bufsz);
	ctx->bufsz = bufsz;
	ctx->bufend = ctx->buf + (bufsz / sizeof(uint32_t));
	ctx->bufptr = ctx->bufend;

	acebitstream_refill_bits(ctx);
	return ctx;
}

void
acebitstream_free(acebitstream_ctx_t *ctx)
{
	free(ctx->buf);
	free(ctx);
}

uint32_t
acebitstream_peek_bits(acebitstream_ctx_t *ctx, size_t n)
{
	assert(n > 0 && n < 32);
	if (ctx->bitcount < n) {
		acebitstream_refill_bits(ctx);
	}
	return ctx->bits >> (64 - n);
}

uint32_t
acebitstream_skip_bits(acebitstream_ctx_t *ctx, size_t n)
{
	assert(n > 0 && n < 32);
	if (ctx->bitcount < n) {
		acebitstream_refill_bits(ctx);
		if (ctx->bitcount < n)
			return ACEBITSTREAM_EOF;
	}
	ctx->bits <<= n;
	ctx->bitcount -= n;
	return 0;
}

uint32_t
acebitstream_read_bits(acebitstream_ctx_t *ctx, size_t n)
{
	uint32_t value, rv;

	value = acebitstream_peek_bits(ctx, n);
	rv = acebitstream_skip_bits(ctx, n);
	if (rv == ACEBITSTREAM_EOF)
		return rv;
	return value;
}

