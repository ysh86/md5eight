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

/* struct MD5Context { */
	uint8_t digest[4*4]; /* uint32_t le x4 */
	uint8_t buf[64];
/* }; */

void MD5Transform (const uint8_t in[64]);

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void
MD5Init()
{
	digest[4*0+3] = 0x67; digest[4*0+2] = 0x45; digest[4*0+1] = 0x23; digest[4*0+0] = 0x01;
	digest[4*1+3] = 0xef; digest[4*1+2] = 0xcd; digest[4*1+1] = 0xab; digest[4*1+0] = 0x89;
	digest[4*2+3] = 0x98; digest[4*2+2] = 0xba; digest[4*2+1] = 0xdc; digest[4*2+0] = 0xfe;
	digest[4*3+3] = 0x10; digest[4*3+2] = 0x32; digest[4*3+1] = 0x54; digest[4*3+0] = 0x76;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void
MD5Update(const uint8_t *in, uint32_t len)
{
	/* Process data in 64-byte chunks */

	while (len >= 64) {
		MD5Transform(in);
		in += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */

	memcpy(buf, in, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void
MD5Final(uint32_t len)
{
	uint8_t count;
	uint8_t *p;
	uint32_t len_lo;
	uint32_t len_hi;

	/* Compute number of bytes mod 64 */
	count = len & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	p = buf + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		MD5Transform(buf);

		/* Now fill the next block with 56 bytes */
		memset(buf, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count-8);
	}

	/* Append length in bits and transform */

	len_lo = (len << 3) & 0xffffffff;
	len_hi = len >> 29;
	buf[56+0] = len_lo; buf[56+1] = len_lo >> 8; buf[56+2] = len_lo >> 16; buf[56+3] = len_lo >> 24;
	buf[60+0] = len_hi; buf[60+1] = len_hi >> 8; buf[60+2] = len_hi >> 16; buf[60+3] = len_hi >> 24;
	MD5Transform(buf);
}

/* This is the central step in the MD5 algorithm. */
static uint8_t F1CONST[] = {
0xd7,0x6a,0xa4,0x78,
0xe8,0xc7,0xb7,0x56,
0x24,0x20,0x70,0xdb,
0xc1,0xbd,0xce,0xee,
0xf5,0x7c,0x0f,0xaf,
0x47,0x87,0xc6,0x2a,
0xa8,0x30,0x46,0x13,
0xfd,0x46,0x95,0x01,
0x69,0x80,0x98,0xd8,
0x8b,0x44,0xf7,0xaf,
0xff,0xff,0x5b,0xb1,
0x89,0x5c,0xd7,0xbe,
0x6b,0x90,0x11,0x22,
0xfd,0x98,0x71,0x93,
0xa6,0x79,0x43,0x8e,
0x49,0xb4,0x08,0x21,
};
static uint8_t F2CONST[] = {
0xf6,0x1e,0x25,0x62,
0xc0,0x40,0xb3,0x40,
0x26,0x5e,0x5a,0x51,
0xe9,0xb6,0xc7,0xaa,
0xd6,0x2f,0x10,0x5d,
0x02,0x44,0x14,0x53,
0xd8,0xa1,0xe6,0x81,
0xe7,0xd3,0xfb,0xc8,
0x21,0xe1,0xcd,0xe6,
0xc3,0x37,0x07,0xd6,
0xf4,0xd5,0x0d,0x87,
0x45,0x5a,0x14,0xed,
0xa9,0xe3,0xe9,0x05,
0xfc,0xef,0xa3,0xf8,
0x67,0x6f,0x02,0xd9,
0x8d,0x2a,0x4c,0x8a,
};
static uint8_t F3CONST[] = {
0xff,0xfa,0x39,0x42,
0x87,0x71,0xf6,0x81,
0x6d,0x9d,0x61,0x22,
0xfd,0xe5,0x38,0x0c,
0xa4,0xbe,0xea,0x44,
0x4b,0xde,0xcf,0xa9,
0xf6,0xbb,0x4b,0x60,
0xbe,0xbf,0xbc,0x70,
0x28,0x9b,0x7e,0xc6,
0xea,0xa1,0x27,0xfa,
0xd4,0xef,0x30,0x85,
0x04,0x88,0x1d,0x05,
0xd9,0xd4,0xd0,0x39,
0xe6,0xdb,0x99,0xe5,
0x1f,0xa2,0x7c,0xf8,
0xc4,0xac,0x56,0x65,
};
static uint8_t F4CONST[] = {
0xf4,0x29,0x22,0x44,
0x43,0x2a,0xff,0x97,
0xab,0x94,0x23,0xa7,
0xfc,0x93,0xa0,0x39,
0x65,0x5b,0x59,0xc3,
0x8f,0x0c,0xcc,0x92,
0xff,0xef,0xf4,0x7d,
0x85,0x84,0x5d,0xd1,
0x6f,0xa8,0x7e,0x4f,
0xfe,0x2c,0xe6,0xe0,
0xa3,0x01,0x43,0x14,
0x4e,0x08,0x11,0xa1,
0xf7,0x53,0x7e,0x82,
0xbd,0x3a,0xf2,0x35,
0x2a,0xd7,0xd2,0xbb,
0xeb,0x86,0xd3,0x91,
};
void MD5STEP(uint8_t w[4], uint8_t t[4], const uint8_t data[4], uint8_t cnst[4], uint8_t x[4], uint8_t s)
{
	uint32_t ww = (w[0] | (w[1] << 8) | (w[2] << 16) | (w[3] << 24));
	uint32_t tt = (t[0] | (t[1] << 8) | (t[2] << 16) | (t[3] << 24));
	uint32_t dd = (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
	uint32_t cc = (cnst[3] | (cnst[2] << 8) | (cnst[1] << 16) | (cnst[0] << 24));
	uint32_t xx = (x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24));

	ww += tt + dd + cc;
	//ww &= 0xffffffff;
	ww = ww<<s | ww>>(32-s);
	ww += xx;

	w[0] = ww;
	w[1] = ww >> 8;
	w[2] = ww >> 16;
	w[3] = ww >> 24;
}
void MD5STEP_F1(uint8_t w[4], uint8_t x[4], uint8_t y[4], uint8_t z[4], const uint8_t data[4], uint8_t cnst[4], uint8_t s)
{
	uint8_t t[4];

	t[0] = y[0] ^ z[0]; t[1] = y[1] ^ z[1]; t[2] = y[2] ^ z[2]; t[3] = y[3] ^ z[3];
	t[0] = x[0] & t[0]; t[1] = x[1] & t[1]; t[2] = x[2] & t[2]; t[3] = x[3] & t[3];
	t[0] = z[0] ^ t[0]; t[1] = z[1] ^ t[1]; t[2] = z[2] ^ t[2]; t[3] = z[3] ^ t[3];

	MD5STEP(w, t, data, cnst, x, s);
}
void MD5STEP_F2(uint8_t w[4], uint8_t x[4], uint8_t y[4], uint8_t z[4], const uint8_t data[4], uint8_t cnst[4], uint8_t s)
{
	uint8_t t[4];

	t[0] = x[0] ^ y[0]; t[1] = x[1] ^ y[1]; t[2] = x[2] ^ y[2]; t[3] = x[3] ^ y[3];
	t[0] = z[0] & t[0]; t[1] = z[1] & t[1]; t[2] = z[2] & t[2]; t[3] = z[3] & t[3];
	t[0] = y[0] ^ t[0]; t[1] = y[1] ^ t[1]; t[2] = y[2] ^ t[2]; t[3] = y[3] ^ t[3];

	MD5STEP(w, t, data, cnst, x, s);
}
void MD5STEP_F3(uint8_t w[4], uint8_t x[4], uint8_t y[4], uint8_t z[4], const uint8_t data[4], uint8_t cnst[4], uint8_t s)
{
	uint8_t t[4];

	t[0] = x[0] ^ y[0]; t[1] = x[1] ^ y[1]; t[2] = x[2] ^ y[2]; t[3] = x[3] ^ y[3];
	t[0] = t[0] ^ z[0]; t[1] = t[1] ^ z[1]; t[2] = t[2] ^ z[2]; t[3] = t[3] ^ z[3];

	MD5STEP(w, t, data, cnst, x, s);
}
void MD5STEP_F4(uint8_t w[4], uint8_t x[4], uint8_t y[4], uint8_t z[4], const uint8_t data[4], uint8_t cnst[4], uint8_t s)
{
	uint8_t t[4];

	t[0] = x[0] | ~z[0]; t[1] = x[1] | ~z[1]; t[2] = x[2] | ~z[2]; t[3] = x[3] | ~z[3];
	t[0] = y[0] ^  t[0]; t[1] = y[1] ^  t[1]; t[2] = y[2] ^  t[2]; t[3] = y[3] ^  t[3];

	MD5STEP(w, t, data, cnst, x, s);
}

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void
MD5Transform(const uint8_t in[64])
{
	uint8_t a[4], b[4], c[4], d[4];

	a[0] = digest[0 +0]; a[1] = digest[0 +1]; a[2] = digest[0 +2]; a[3] = digest[0 +3];
	b[0] = digest[4 +0]; b[1] = digest[4 +1]; b[2] = digest[4 +2]; b[3] = digest[4 +3];
	c[0] = digest[8 +0]; c[1] = digest[8 +1]; c[2] = digest[8 +2]; c[3] = digest[8 +3];
	d[0] = digest[12+0]; d[1] = digest[12+1]; d[2] = digest[12+2]; d[3] = digest[12+3];

	MD5STEP_F1(a, b, c, d, &in[ 0*4], &F1CONST[ 0*4],  7);
	MD5STEP_F1(d, a, b, c, &in[ 1*4], &F1CONST[ 1*4], 12);
	MD5STEP_F1(c, d, a, b, &in[ 2*4], &F1CONST[ 2*4], 17);
	MD5STEP_F1(b, c, d, a, &in[ 3*4], &F1CONST[ 3*4], 22);
	MD5STEP_F1(a, b, c, d, &in[ 4*4], &F1CONST[ 4*4],  7);
	MD5STEP_F1(d, a, b, c, &in[ 5*4], &F1CONST[ 5*4], 12);
	MD5STEP_F1(c, d, a, b, &in[ 6*4], &F1CONST[ 6*4], 17);
	MD5STEP_F1(b, c, d, a, &in[ 7*4], &F1CONST[ 7*4], 22);
	MD5STEP_F1(a, b, c, d, &in[ 8*4], &F1CONST[ 8*4],  7);
	MD5STEP_F1(d, a, b, c, &in[ 9*4], &F1CONST[ 9*4], 12);
	MD5STEP_F1(c, d, a, b, &in[10*4], &F1CONST[10*4], 17);
	MD5STEP_F1(b, c, d, a, &in[11*4], &F1CONST[11*4], 22);
	MD5STEP_F1(a, b, c, d, &in[12*4], &F1CONST[12*4],  7);
	MD5STEP_F1(d, a, b, c, &in[13*4], &F1CONST[13*4], 12);
	MD5STEP_F1(c, d, a, b, &in[14*4], &F1CONST[14*4], 17);
	MD5STEP_F1(b, c, d, a, &in[15*4], &F1CONST[15*4], 22);

	MD5STEP_F2(a, b, c, d, &in[ 1*4], &F2CONST[ 0*4],  5);
	MD5STEP_F2(d, a, b, c, &in[ 6*4], &F2CONST[ 1*4],  9);
	MD5STEP_F2(c, d, a, b, &in[11*4], &F2CONST[ 2*4], 14);
	MD5STEP_F2(b, c, d, a, &in[ 0*4], &F2CONST[ 3*4], 20);
	MD5STEP_F2(a, b, c, d, &in[ 5*4], &F2CONST[ 4*4],  5);
	MD5STEP_F2(d, a, b, c, &in[10*4], &F2CONST[ 5*4],  9);
	MD5STEP_F2(c, d, a, b, &in[15*4], &F2CONST[ 6*4], 14);
	MD5STEP_F2(b, c, d, a, &in[ 4*4], &F2CONST[ 7*4], 20);
	MD5STEP_F2(a, b, c, d, &in[ 9*4], &F2CONST[ 8*4],  5);
	MD5STEP_F2(d, a, b, c, &in[14*4], &F2CONST[ 9*4],  9);
	MD5STEP_F2(c, d, a, b, &in[ 3*4], &F2CONST[10*4], 14);
	MD5STEP_F2(b, c, d, a, &in[ 8*4], &F2CONST[11*4], 20);
	MD5STEP_F2(a, b, c, d, &in[13*4], &F2CONST[12*4],  5);
	MD5STEP_F2(d, a, b, c, &in[ 2*4], &F2CONST[13*4],  9);
	MD5STEP_F2(c, d, a, b, &in[ 7*4], &F2CONST[14*4], 14);
	MD5STEP_F2(b, c, d, a, &in[12*4], &F2CONST[15*4], 20);

	MD5STEP_F3(a, b, c, d, &in[ 5*4], &F3CONST[ 0*4],  4);
	MD5STEP_F3(d, a, b, c, &in[ 8*4], &F3CONST[ 1*4], 11);
	MD5STEP_F3(c, d, a, b, &in[11*4], &F3CONST[ 2*4], 16);
	MD5STEP_F3(b, c, d, a, &in[14*4], &F3CONST[ 3*4], 23);
	MD5STEP_F3(a, b, c, d, &in[ 1*4], &F3CONST[ 4*4],  4);
	MD5STEP_F3(d, a, b, c, &in[ 4*4], &F3CONST[ 5*4], 11);
	MD5STEP_F3(c, d, a, b, &in[ 7*4], &F3CONST[ 6*4], 16);
	MD5STEP_F3(b, c, d, a, &in[10*4], &F3CONST[ 7*4], 23);
	MD5STEP_F3(a, b, c, d, &in[13*4], &F3CONST[ 8*4],  4);
	MD5STEP_F3(d, a, b, c, &in[ 0*4], &F3CONST[ 9*4], 11);
	MD5STEP_F3(c, d, a, b, &in[ 3*4], &F3CONST[10*4], 16);
	MD5STEP_F3(b, c, d, a, &in[ 6*4], &F3CONST[11*4], 23);
	MD5STEP_F3(a, b, c, d, &in[ 9*4], &F3CONST[12*4],  4);
	MD5STEP_F3(d, a, b, c, &in[12*4], &F3CONST[13*4], 11);
	MD5STEP_F3(c, d, a, b, &in[15*4], &F3CONST[14*4], 16);
	MD5STEP_F3(b, c, d, a, &in[ 2*4], &F3CONST[15*4], 23);

	MD5STEP_F4(a, b, c, d, &in[ 0*4], &F4CONST[ 0*4],  6);
	MD5STEP_F4(d, a, b, c, &in[ 7*4], &F4CONST[ 1*4], 10);
	MD5STEP_F4(c, d, a, b, &in[14*4], &F4CONST[ 2*4], 15);
	MD5STEP_F4(b, c, d, a, &in[ 5*4], &F4CONST[ 3*4], 21);
	MD5STEP_F4(a, b, c, d, &in[12*4], &F4CONST[ 4*4],  6);
	MD5STEP_F4(d, a, b, c, &in[ 3*4], &F4CONST[ 5*4], 10);
	MD5STEP_F4(c, d, a, b, &in[10*4], &F4CONST[ 6*4], 15);
	MD5STEP_F4(b, c, d, a, &in[ 1*4], &F4CONST[ 7*4], 21);
	MD5STEP_F4(a, b, c, d, &in[ 8*4], &F4CONST[ 8*4],  6);
	MD5STEP_F4(d, a, b, c, &in[15*4], &F4CONST[ 9*4], 10);
	MD5STEP_F4(c, d, a, b, &in[ 6*4], &F4CONST[10*4], 15);
	MD5STEP_F4(b, c, d, a, &in[13*4], &F4CONST[11*4], 21);
	MD5STEP_F4(a, b, c, d, &in[ 4*4], &F4CONST[12*4],  6);
	MD5STEP_F4(d, a, b, c, &in[11*4], &F4CONST[13*4], 10);
	MD5STEP_F4(c, d, a, b, &in[ 2*4], &F4CONST[14*4], 15);
	MD5STEP_F4(b, c, d, a, &in[ 9*4], &F4CONST[15*4], 21);

	*(uint32_t *)(&digest[0])  += (a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24));
	*(uint32_t *)(&digest[4])  += (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24));
	*(uint32_t *)(&digest[8])  += (c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24));
	*(uint32_t *)(&digest[12]) += (d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24));
}


/* Simple test program.  Can use it to manually run the tests from
   RFC1321 for example.  */
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{
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
		MD5Init ();
		len = strlen (argv[j]);
		MD5Update ((const uint8_t *) argv[j], len);
		MD5Final (len);
		for (i = 0; i < 16; i++)
		{
			printf ("%02x", digest[i]);
		}
		printf ("\n");
	}
	return 0;
}
