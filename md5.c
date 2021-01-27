/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

/* This code was modified in 1997 by Jim Kingdon of Cyclic Software to
   not require an integer type which is exactly 32 bits.  This work
   draws on the changes for the same purpose by Tatu Ylonen
   <ylo@cs.hut.fi> as part of SSH, but since I didn't actually use
   that code, there is no copyright issue.  I hereby disclaim
   copyright in any changes I have made; this code remains in the
   public domain.  */

#include <string.h>	/* for memcpy() */
#include <stdint.h>

struct MD5Context {
	uint32_t buf[4];
	unsigned char in[64];
};

void MD5Transform (uint32_t buf[4], const unsigned char in[64]);

/* Little-endian byte-swapping routines.  Note that these do not
   depend on the size of datatypes such as uint32_t, nor do they require
   us to detect the endianness of the machine we are running on.  It
   is possible they should be macros for speed, but I would be
   surprised if they were a performance bottleneck for MD5.  */

static uint32_t
getu32 (const unsigned char *addr)
{
	return (((((unsigned long)addr[3] << 8) | addr[2]) << 8)
		| addr[1]) << 8 | addr[0];
}

static void
putu32 (uint32_t data, unsigned char *addr)
{
	addr[0] = (unsigned char)data;
	addr[1] = (unsigned char)(data >> 8);
	addr[2] = (unsigned char)(data >> 16);
	addr[3] = (unsigned char)(data >> 24);
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void
MD5Init(struct MD5Context *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void
MD5Update(struct MD5Context *ctx, unsigned char const *buf, uint32_t len)
{
	/* Process data in 64-byte chunks */

	while (len >= 64) {
		MD5Transform(ctx->buf, buf);
		buf += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */

	memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void
MD5Final(unsigned char digest[16], struct MD5Context *ctx, uint32_t len)
{
	unsigned count;
	unsigned char *p;

	/* Compute number of bytes mod 64 */
	count = len & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	p = ctx->in + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		MD5Transform(ctx->buf, ctx->in);

		/* Now fill the next block with 56 bytes */
		memset(ctx->in, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count-8);
	}

	/* Append length in bits and transform */
	putu32((len << 3) & 0xffffffff, ctx->in + 56);
	putu32(len >> 29, ctx->in + 60);
	MD5Transform(ctx->buf, ctx->in);

	putu32(ctx->buf[0], digest);
	putu32(ctx->buf[1], digest + 4);
	putu32(ctx->buf[2], digest + 8);
	putu32(ctx->buf[3], digest + 12);
}

/* This is the central step in the MD5 algorithm. */
uint32_t MD5STEP_F1(uint32_t w, uint32_t x, uint32_t y, uint32_t z, uint32_t data, uint32_t s)
{
	w += (z ^ (x & (y ^ z))) + data;
	w &= 0xffffffff;
	w = w<<s | w>>(32-s);
	w += x;
	return w;
}
uint32_t MD5STEP_F2(uint32_t w, uint32_t x, uint32_t y, uint32_t z, uint32_t data, uint32_t s)
{
	w += (y ^ (z & (x ^ y))) + data;
	w &= 0xffffffff;
	w = w<<s | w>>(32-s);
	w += x;
	return w;
}
uint32_t MD5STEP_F3(uint32_t w, uint32_t x, uint32_t y, uint32_t z, uint32_t data, uint32_t s)
{
	w += (x ^ y ^ z) + data;
	w &= 0xffffffff;
	w = w<<s | w>>(32-s);
	w += x;
	return w;
}
uint32_t MD5STEP_F4(uint32_t w, uint32_t x, uint32_t y, uint32_t z, uint32_t data, uint32_t s)
{
	w += (y ^ (x | ~z)) + data;
	w &= 0xffffffff;
	w = w<<s | w>>(32-s);
	w += x;
	return w;
}

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void
MD5Transform(uint32_t buf[4], const unsigned char inraw[64])
{
	uint32_t a, b, c, d;
	uint32_t in[16];
	int i;

	for (i = 0; i < 16; ++i)
		in[i] = getu32 (inraw + 4 * i);

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	a = MD5STEP_F1(a, b, c, d, in[ 0]+0xd76aa478,  7);
	d = MD5STEP_F1(d, a, b, c, in[ 1]+0xe8c7b756, 12);
	c = MD5STEP_F1(c, d, a, b, in[ 2]+0x242070db, 17);
	b = MD5STEP_F1(b, c, d, a, in[ 3]+0xc1bdceee, 22);
	a = MD5STEP_F1(a, b, c, d, in[ 4]+0xf57c0faf,  7);
	d = MD5STEP_F1(d, a, b, c, in[ 5]+0x4787c62a, 12);
	c = MD5STEP_F1(c, d, a, b, in[ 6]+0xa8304613, 17);
	b = MD5STEP_F1(b, c, d, a, in[ 7]+0xfd469501, 22);
	a = MD5STEP_F1(a, b, c, d, in[ 8]+0x698098d8,  7);
	d = MD5STEP_F1(d, a, b, c, in[ 9]+0x8b44f7af, 12);
	c = MD5STEP_F1(c, d, a, b, in[10]+0xffff5bb1, 17);
	b = MD5STEP_F1(b, c, d, a, in[11]+0x895cd7be, 22);
	a = MD5STEP_F1(a, b, c, d, in[12]+0x6b901122,  7);
	d = MD5STEP_F1(d, a, b, c, in[13]+0xfd987193, 12);
	c = MD5STEP_F1(c, d, a, b, in[14]+0xa679438e, 17);
	b = MD5STEP_F1(b, c, d, a, in[15]+0x49b40821, 22);

	a = MD5STEP_F2(a, b, c, d, in[ 1]+0xf61e2562,  5);
	d = MD5STEP_F2(d, a, b, c, in[ 6]+0xc040b340,  9);
	c = MD5STEP_F2(c, d, a, b, in[11]+0x265e5a51, 14);
	b = MD5STEP_F2(b, c, d, a, in[ 0]+0xe9b6c7aa, 20);
	a = MD5STEP_F2(a, b, c, d, in[ 5]+0xd62f105d,  5);
	d = MD5STEP_F2(d, a, b, c, in[10]+0x02441453,  9);
	c = MD5STEP_F2(c, d, a, b, in[15]+0xd8a1e681, 14);
	b = MD5STEP_F2(b, c, d, a, in[ 4]+0xe7d3fbc8, 20);
	a = MD5STEP_F2(a, b, c, d, in[ 9]+0x21e1cde6,  5);
	d = MD5STEP_F2(d, a, b, c, in[14]+0xc33707d6,  9);
	c = MD5STEP_F2(c, d, a, b, in[ 3]+0xf4d50d87, 14);
	b = MD5STEP_F2(b, c, d, a, in[ 8]+0x455a14ed, 20);
	a = MD5STEP_F2(a, b, c, d, in[13]+0xa9e3e905,  5);
	d = MD5STEP_F2(d, a, b, c, in[ 2]+0xfcefa3f8,  9);
	c = MD5STEP_F2(c, d, a, b, in[ 7]+0x676f02d9, 14);
	b = MD5STEP_F2(b, c, d, a, in[12]+0x8d2a4c8a, 20);

	a = MD5STEP_F3(a, b, c, d, in[ 5]+0xfffa3942,  4);
	d = MD5STEP_F3(d, a, b, c, in[ 8]+0x8771f681, 11);
	c = MD5STEP_F3(c, d, a, b, in[11]+0x6d9d6122, 16);
	b = MD5STEP_F3(b, c, d, a, in[14]+0xfde5380c, 23);
	a = MD5STEP_F3(a, b, c, d, in[ 1]+0xa4beea44,  4);
	d = MD5STEP_F3(d, a, b, c, in[ 4]+0x4bdecfa9, 11);
	c = MD5STEP_F3(c, d, a, b, in[ 7]+0xf6bb4b60, 16);
	b = MD5STEP_F3(b, c, d, a, in[10]+0xbebfbc70, 23);
	a = MD5STEP_F3(a, b, c, d, in[13]+0x289b7ec6,  4);
	d = MD5STEP_F3(d, a, b, c, in[ 0]+0xeaa127fa, 11);
	c = MD5STEP_F3(c, d, a, b, in[ 3]+0xd4ef3085, 16);
	b = MD5STEP_F3(b, c, d, a, in[ 6]+0x04881d05, 23);
	a = MD5STEP_F3(a, b, c, d, in[ 9]+0xd9d4d039,  4);
	d = MD5STEP_F3(d, a, b, c, in[12]+0xe6db99e5, 11);
	c = MD5STEP_F3(c, d, a, b, in[15]+0x1fa27cf8, 16);
	b = MD5STEP_F3(b, c, d, a, in[ 2]+0xc4ac5665, 23);

	a = MD5STEP_F4(a, b, c, d, in[ 0]+0xf4292244,  6);
	d = MD5STEP_F4(d, a, b, c, in[ 7]+0x432aff97, 10);
	c = MD5STEP_F4(c, d, a, b, in[14]+0xab9423a7, 15);
	b = MD5STEP_F4(b, c, d, a, in[ 5]+0xfc93a039, 21);
	a = MD5STEP_F4(a, b, c, d, in[12]+0x655b59c3,  6);
	d = MD5STEP_F4(d, a, b, c, in[ 3]+0x8f0ccc92, 10);
	c = MD5STEP_F4(c, d, a, b, in[10]+0xffeff47d, 15);
	b = MD5STEP_F4(b, c, d, a, in[ 1]+0x85845dd1, 21);
	a = MD5STEP_F4(a, b, c, d, in[ 8]+0x6fa87e4f,  6);
	d = MD5STEP_F4(d, a, b, c, in[15]+0xfe2ce6e0, 10);
	c = MD5STEP_F4(c, d, a, b, in[ 6]+0xa3014314, 15);
	b = MD5STEP_F4(b, c, d, a, in[13]+0x4e0811a1, 21);
	a = MD5STEP_F4(a, b, c, d, in[ 4]+0xf7537e82,  6);
	d = MD5STEP_F4(d, a, b, c, in[11]+0xbd3af235, 10);
	c = MD5STEP_F4(c, d, a, b, in[ 2]+0x2ad7d2bb, 15);
	b = MD5STEP_F4(b, c, d, a, in[ 9]+0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}


/* Simple test program.  Can use it to manually run the tests from
   RFC1321 for example.  */
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{
	struct MD5Context context;
	unsigned char checksum[16];
	int i;
	int j;
	uint32_t len;

	if (argc < 2)
	{
		fprintf (stderr, "usage: %s string-to-hash\n", argv[0]);
		exit (1);
	}
	for (j = 1; j < argc; ++j)
	{
		printf ("MD5 (\"%s\") = ", argv[j]);
		MD5Init (&context);
		len = strlen (argv[j]);
		MD5Update (&context, (unsigned char const *) argv[j], len);
		MD5Final (checksum, &context, len);
		for (i = 0; i < 16; i++)
		{
			printf ("%02x", (unsigned int) checksum[i]);
		}
		printf ("\n");
	}
	return 0;
}
