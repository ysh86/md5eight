char F1CONST[16*4] = {
0x78,0xa4,0x6a,0xd7,
0x56,0xb7,0xc7,0xe8,
0xdb,0x70,0x20,0x24,
0xee,0xce,0xbd,0xc1,
0xaf,0x0f,0x7c,0xf5,
0x2a,0xc6,0x87,0x47,
0x13,0x46,0x30,0xa8,
0x01,0x95,0x46,0xfd,
0xd8,0x98,0x80,0x69,
0xaf,0xf7,0x44,0x8b,
0xb1,0x5b,0xff,0xff,
0xbe,0xd7,0x5c,0x89,
0x22,0x11,0x90,0x6b,
0x93,0x71,0x98,0xfd,
0x8e,0x43,0x79,0xa6,
0x21,0x08,0xb4,0x49
};
char F2CONST[16*4] = {
0x62,0x25,0x1e,0xf6,
0x40,0xb3,0x40,0xc0,
0x51,0x5a,0x5e,0x26,
0xaa,0xc7,0xb6,0xe9,
0x5d,0x10,0x2f,0xd6,
0x53,0x14,0x44,0x02,
0x81,0xe6,0xa1,0xd8,
0xc8,0xfb,0xd3,0xe7,
0xe6,0xcd,0xe1,0x21,
0xd6,0x07,0x37,0xc3,
0x87,0x0d,0xd5,0xf4,
0xed,0x14,0x5a,0x45,
0x05,0xe9,0xe3,0xa9,
0xf8,0xa3,0xef,0xfc,
0xd9,0x02,0x6f,0x67,
0x8a,0x4c,0x2a,0x8d
};
char F3CONST[16*4] = {
0x42,0x39,0xfa,0xff,
0x81,0xf6,0x71,0x87,
0x22,0x61,0x9d,0x6d,
0x0c,0x38,0xe5,0xfd,
0x44,0xea,0xbe,0xa4,
0xa9,0xcf,0xde,0x4b,
0x60,0x4b,0xbb,0xf6,
0x70,0xbc,0xbf,0xbe,
0xc6,0x7e,0x9b,0x28,
0xfa,0x27,0xa1,0xea,
0x85,0x30,0xef,0xd4,
0x05,0x1d,0x88,0x04,
0x39,0xd0,0xd4,0xd9,
0xe5,0x99,0xdb,0xe6,
0xf8,0x7c,0xa2,0x1f,
0x65,0x56,0xac,0xc4
};
char F4CONST[16*4] = {
0x44,0x22,0x29,0xf4,
0x97,0xff,0x2a,0x43,
0xa7,0x23,0x94,0xab,
0x39,0xa0,0x93,0xfc,
0xc3,0x59,0x5b,0x65,
0x92,0xcc,0x0c,0x8f,
0x7d,0xf4,0xef,0xff,
0xd1,0x5d,0x84,0x85,
0x4f,0x7e,0xa8,0x6f,
0xe0,0xe6,0x2c,0xfe,
0x14,0x43,0x01,0xa3,
0xa1,0x11,0x08,0x4e,
0x82,0x7e,0x53,0xf7,
0x35,0xf2,0x3a,0xbd,
0xbb,0xd2,0xd7,0x2a,
0x91,0xd3,0x86,0xeb
};

char digest[4*4]; /* uint32_t le x4 */
char buf[64];
char len[4];
pnt len20;
char d;

proto char Transf:

func char memset(pnt dst; char val; char len):
char i;
{
	i = 0;
	while (i < len) {
		@(dst)[i] = val;
		i += 1;
	};
}

/*
 * Start MD5 accumulation.
 * Set buffer to mysterious initialization constants.
 */
func char Init:
{
	digest[4*0+0] = 0x01; digest[4*0+1] = 0x23; digest[4*0+2] = 0x45; digest[4*0+3] = 0x67;
	digest[4*1+0] = 0x89; digest[4*1+1] = 0xab; digest[4*1+2] = 0xcd; digest[4*1+3] = 0xef;
	digest[4*2+0] = 0xfe; digest[4*2+1] = 0xdc; digest[4*2+2] = 0xba; digest[4*2+3] = 0x98;
	digest[4*3+0] = 0x76; digest[4*3+1] = 0x54; digest[4*3+2] = 0x32; digest[4*3+3] = 0x10;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
func char Update(pnt in; pnt length):
pnt l;
{
	/* Process data in 64-byte chunks */

	l = 0;
	while (l + 64 <= length) {
		Transf(in + l);
		l += 64;
	};

	/* Handle any remaining bytes of data. */

	move(&buf, in + l, length - l);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
func char Final(pnt len):
char count;
pnt p;
{

	/* Compute number of bytes mod 64 */
	count = @(len)[0] & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	buf[count] = 0x80;
	p = &buf[count + 1];

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		Transf(&buf);

		/* Now fill the next block with 56 bytes */
		memset(&buf, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count-8);
	};

	/* Append length in bits and transform */

	buf[56+0] = @(len)[0] << 3;
	buf[56+1] = (@(len)[1] << 3) | (@(len)[0] >> 5);
	buf[56+2] = (@(len)[2] << 3) | (@(len)[1] >> 5);
	buf[56+3] = (@(len)[3] << 3) | (@(len)[2] >> 5);
	buf[60+0] = @(len)[3] >> 5;
	buf[60+1] = 0;
	buf[60+2] = 0;
	buf[60+3] = 0;
	Transf(&buf);
}

/* This is the central step in the MD5 algorithm. */
func pnt add32(pnt a; pnt b):
char t;
char c;
{
	t = @(a)[0] + @(b)[0];
	if (t < @(a)[0]) {
		c = 1;
	} else {
		c = 0;
	};
	@(a)[0] = t;

	t = @(a)[1] + @(b)[1] + c;
	if (c == 0) {
		if (t < @(a)[1]) {
			c = 1;
		} else {
			c = 0;
		};
	} else {
		if (t <= @(a)[1]) {
			c = 1;
		} else {
			c = 0;
		};
	};
	@(a)[1] = t;

	t = @(a)[2] + @(b)[2] + c;
	if (c == 0) {
		if (t < @(a)[2]) {
			c = 1;
		} else {
			c = 0;
		};
	} else {
		if (t <= @(a)[2]) {
			c = 1;
		} else {
			c = 0;
		};
	};
	@(a)[2] = t;

	@(a)[3] = @(a)[3] + @(b)[3] + c;

	return a;
}
func char rotate(pnt a; pnt left):
char l;
char rm;
char t, tt;
{
	l = left >> 3;
	rm = left & 7;

	while (l > 0) {
		t = @(a)[3];
		@(a)[3] = @(a)[2];
		@(a)[2] = @(a)[1];
		@(a)[1] = @(a)[0];
		@(a)[0] = t;
		l -= 1;
	};

	t = @(a)[0] >> (8-rm);
	@(a)[0] = (@(a)[0]<<rm) | (@(a)[3] >> (8-rm));
	tt = @(a)[1] >> (8-rm);
	@(a)[1] = (@(a)[1]<<rm) | t;
	t = @(a)[2] >> (8-rm);
	@(a)[2] = (@(a)[2]<<rm) | tt;
	@(a)[3] = (@(a)[3]<<rm) | t;
}
func char MD5(pnt w; pnt t; pnt data; pnt cnst; pnt x; char s):
{
	add32(w, add32(add32(t, data), cnst));
	rotate(w, s);
	add32(w, x);
}
func char MD5F1(pnt w; pnt x; pnt y; pnt z; pnt data; pnt cnst; char s):
char t[4];
{
	t[0] = @(y)[0] # @(z)[0]; t[1] = @(y)[1] # @(z)[1]; t[2] = @(y)[2] # @(z)[2]; t[3] = @(y)[3] # @(z)[3];
	t[0] = @(x)[0] & t[0]; t[1] = @(x)[1] & t[1]; t[2] = @(x)[2] & t[2]; t[3] = @(x)[3] & t[3];
	t[0] = @(z)[0] # t[0]; t[1] = @(z)[1] # t[1]; t[2] = @(z)[2] # t[2]; t[3] = @(z)[3] # t[3];

	MD5(w, &t, data, cnst, x, s);
}
func char MD5F2(pnt w; pnt x; pnt y; pnt z; pnt data; pnt cnst; char s):
char t[4];
{
	t[0] = @(x)[0] # @(y)[0]; t[1] = @(x)[1] # @(y)[1]; t[2] = @(x)[2] # @(y)[2]; t[3] = @(x)[3] # @(y)[3];
	t[0] = @(z)[0] & t[0]; t[1] = @(z)[1] & t[1]; t[2] = @(z)[2] & t[2]; t[3] = @(z)[3] & t[3];
	t[0] = @(y)[0] # t[0]; t[1] = @(y)[1] # t[1]; t[2] = @(y)[2] # t[2]; t[3] = @(y)[3] # t[3];

	MD5(w, &t, data, cnst, x, s);
}
func char MD5F3(pnt w; pnt x; pnt y; pnt z; pnt data; pnt cnst; char s):
char t[4];
{
	t[0] = @(x)[0] # @(y)[0]; t[1] = @(x)[1] # @(y)[1]; t[2] = @(x)[2] # @(y)[2]; t[3] = @(x)[3] # @(y)[3];
	t[0] = t[0] # @(z)[0]; t[1] = t[1] # @(z)[1]; t[2] = t[2] # @(z)[2]; t[3] = t[3] # @(z)[3];

	MD5(w, &t, data, cnst, x, s);
}
func char MD5F4(pnt w; pnt x; pnt y; pnt z; pnt data; pnt cnst; char s):
char t[4];
{
	t[0] = @(x)[0] | ~@(z)[0]; t[1] = @(x)[1] | ~@(z)[1]; t[2] = @(x)[2] | ~@(z)[2]; t[3] = @(x)[3] | ~@(z)[3];
	t[0] = @(y)[0] # t[0]; t[1] = @(y)[1] # t[1]; t[2] = @(y)[2] # t[2]; t[3] = @(y)[3] # t[3];

	MD5(w, &t, data, cnst, x, s);
}

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
func char Transf(pnt in):
char a[4], b[4], c[4], d[4];
{
	a[0] = digest[0 +0]; a[1] = digest[0 +1]; a[2] = digest[0 +2]; a[3] = digest[0 +3];
	b[0] = digest[4 +0]; b[1] = digest[4 +1]; b[2] = digest[4 +2]; b[3] = digest[4 +3];
	c[0] = digest[8 +0]; c[1] = digest[8 +1]; c[2] = digest[8 +2]; c[3] = digest[8 +3];
	d[0] = digest[12+0]; d[1] = digest[12+1]; d[2] = digest[12+2]; d[3] = digest[12+3];

	MD5F1(&a, &b, &c, &d, in + ( 0*4), &F1CONST[ 0*4],  7);
	MD5F1(&d, &a, &b, &c, in + ( 1*4), &F1CONST[ 1*4], 12);
	MD5F1(&c, &d, &a, &b, in + ( 2*4), &F1CONST[ 2*4], 17);
	MD5F1(&b, &c, &d, &a, in + ( 3*4), &F1CONST[ 3*4], 22);
	MD5F1(&a, &b, &c, &d, in + ( 4*4), &F1CONST[ 4*4],  7);
	MD5F1(&d, &a, &b, &c, in + ( 5*4), &F1CONST[ 5*4], 12);
	MD5F1(&c, &d, &a, &b, in + ( 6*4), &F1CONST[ 6*4], 17);
	MD5F1(&b, &c, &d, &a, in + ( 7*4), &F1CONST[ 7*4], 22);
	MD5F1(&a, &b, &c, &d, in + ( 8*4), &F1CONST[ 8*4],  7);
	MD5F1(&d, &a, &b, &c, in + ( 9*4), &F1CONST[ 9*4], 12);
	MD5F1(&c, &d, &a, &b, in + (10*4), &F1CONST[10*4], 17);
	MD5F1(&b, &c, &d, &a, in + (11*4), &F1CONST[11*4], 22);
	MD5F1(&a, &b, &c, &d, in + (12*4), &F1CONST[12*4],  7);
	MD5F1(&d, &a, &b, &c, in + (13*4), &F1CONST[13*4], 12);
	MD5F1(&c, &d, &a, &b, in + (14*4), &F1CONST[14*4], 17);
	MD5F1(&b, &c, &d, &a, in + (15*4), &F1CONST[15*4], 22);

	MD5F2(&a, &b, &c, &d, in + ( 1*4), &F2CONST[ 0*4],  5);
	MD5F2(&d, &a, &b, &c, in + ( 6*4), &F2CONST[ 1*4],  9);
	MD5F2(&c, &d, &a, &b, in + (11*4), &F2CONST[ 2*4], 14);
	MD5F2(&b, &c, &d, &a, in + ( 0*4), &F2CONST[ 3*4], 20);
	MD5F2(&a, &b, &c, &d, in + ( 5*4), &F2CONST[ 4*4],  5);
	MD5F2(&d, &a, &b, &c, in + (10*4), &F2CONST[ 5*4],  9);
	MD5F2(&c, &d, &a, &b, in + (15*4), &F2CONST[ 6*4], 14);
	MD5F2(&b, &c, &d, &a, in + ( 4*4), &F2CONST[ 7*4], 20);
	MD5F2(&a, &b, &c, &d, in + ( 9*4), &F2CONST[ 8*4],  5);
	MD5F2(&d, &a, &b, &c, in + (14*4), &F2CONST[ 9*4],  9);
	MD5F2(&c, &d, &a, &b, in + ( 3*4), &F2CONST[10*4], 14);
	MD5F2(&b, &c, &d, &a, in + ( 8*4), &F2CONST[11*4], 20);
	MD5F2(&a, &b, &c, &d, in + (13*4), &F2CONST[12*4],  5);
	MD5F2(&d, &a, &b, &c, in + ( 2*4), &F2CONST[13*4],  9);
	MD5F2(&c, &d, &a, &b, in + ( 7*4), &F2CONST[14*4], 14);
	MD5F2(&b, &c, &d, &a, in + (12*4), &F2CONST[15*4], 20);

	MD5F3(&a, &b, &c, &d, in + ( 5*4), &F3CONST[ 0*4],  4);
	MD5F3(&d, &a, &b, &c, in + ( 8*4), &F3CONST[ 1*4], 11);
	MD5F3(&c, &d, &a, &b, in + (11*4), &F3CONST[ 2*4], 16);
	MD5F3(&b, &c, &d, &a, in + (14*4), &F3CONST[ 3*4], 23);
	MD5F3(&a, &b, &c, &d, in + ( 1*4), &F3CONST[ 4*4],  4);
	MD5F3(&d, &a, &b, &c, in + ( 4*4), &F3CONST[ 5*4], 11);
	MD5F3(&c, &d, &a, &b, in + ( 7*4), &F3CONST[ 6*4], 16);
	MD5F3(&b, &c, &d, &a, in + (10*4), &F3CONST[ 7*4], 23);
	MD5F3(&a, &b, &c, &d, in + (13*4), &F3CONST[ 8*4],  4);
	MD5F3(&d, &a, &b, &c, in + ( 0*4), &F3CONST[ 9*4], 11);
	MD5F3(&c, &d, &a, &b, in + ( 3*4), &F3CONST[10*4], 16);
	MD5F3(&b, &c, &d, &a, in + ( 6*4), &F3CONST[11*4], 23);
	MD5F3(&a, &b, &c, &d, in + ( 9*4), &F3CONST[12*4],  4);
	MD5F3(&d, &a, &b, &c, in + (12*4), &F3CONST[13*4], 11);
	MD5F3(&c, &d, &a, &b, in + (15*4), &F3CONST[14*4], 16);
	MD5F3(&b, &c, &d, &a, in + ( 2*4), &F3CONST[15*4], 23);

	MD5F4(&a, &b, &c, &d, in + ( 0*4), &F4CONST[ 0*4],  6);
	MD5F4(&d, &a, &b, &c, in + ( 7*4), &F4CONST[ 1*4], 10);
	MD5F4(&c, &d, &a, &b, in + (14*4), &F4CONST[ 2*4], 15);
	MD5F4(&b, &c, &d, &a, in + ( 5*4), &F4CONST[ 3*4], 21);
	MD5F4(&a, &b, &c, &d, in + (12*4), &F4CONST[ 4*4],  6);
	MD5F4(&d, &a, &b, &c, in + ( 3*4), &F4CONST[ 5*4], 10);
	MD5F4(&c, &d, &a, &b, in + (10*4), &F4CONST[ 6*4], 15);
	MD5F4(&b, &c, &d, &a, in + ( 1*4), &F4CONST[ 7*4], 21);
	MD5F4(&a, &b, &c, &d, in + ( 8*4), &F4CONST[ 8*4],  6);
	MD5F4(&d, &a, &b, &c, in + (15*4), &F4CONST[ 9*4], 10);
	MD5F4(&c, &d, &a, &b, in + ( 6*4), &F4CONST[10*4], 15);
	MD5F4(&b, &c, &d, &a, in + (13*4), &F4CONST[11*4], 21);
	MD5F4(&a, &b, &c, &d, in + ( 4*4), &F4CONST[12*4],  6);
	MD5F4(&d, &a, &b, &c, in + (11*4), &F4CONST[13*4], 10);
	MD5F4(&c, &d, &a, &b, in + ( 2*4), &F4CONST[14*4], 15);
	MD5F4(&b, &c, &d, &a, in + ( 9*4), &F4CONST[15*4], 21);

	add32(&digest+ 0, &a);
	add32(&digest+ 4, &b);
	add32(&digest+ 8, &c);
	add32(&digest+12, &d);
}


/* Simple test program. */
{
	/* S3.ROM: 256KB = 0xC0000 - 0xFFFFF */
	len20 = 0x04000;
	len[0] = 0; len[1] = 0x40; len[2] = 0; len[3] = 0;

	Init;
	Update(0xC0000, len20);
	Final(&len);

	d = 0;
	do {
		printf("%2x", digest[d]);
		d += 1;
	} until (d >= 16);
	printf("  S3.ROM^M^J");
}
