'use strict';

const pb64 = require('./pb64.js');

// This is an implementation of the Unix password
// encryption scheme using DES.

// S-boxes and permutation tables were snatched 
// from the file /usr/src/libc/gen/crypt.c found in
// the source code archive of Unix V7 dated 1978.
// They are for the most part also publicly available
// in "Federal Information Processing Standards
// Publication 46: Data Encryption Standard",
// published on January 17, 1977.

const IP = [ 58, 50, 42, 34, 26, 18, 10, 2,
			 60, 52, 44, 36, 28, 20, 12, 4,
			 62, 54, 46, 38, 30, 22, 14, 6,
			 64, 56, 48, 40, 32, 24, 16, 8,
			 57, 49, 41, 33, 25, 17, 9, 1,
			 59, 51, 43, 35, 27, 19, 11, 3,
			 61, 53, 45, 37, 29, 21, 13, 5,
			 63, 55, 47, 39, 31, 23, 15, 7 ];

const FP = [ 40, 8, 48, 16, 56, 24, 64, 32,
			 39, 7, 47, 15, 55, 23, 63, 31,
			 38, 6, 46, 14, 54, 22, 62, 30,
			 37, 5, 45, 13, 53, 21, 61, 29,
			 36, 4, 44, 12, 52, 20, 60, 28,
			 35, 3, 43, 11, 51, 19, 59, 27,
			 34, 2, 42, 10, 50, 18, 58, 26,
			 33, 1, 41, 9, 49, 17, 57, 25 ];

const PC1_C = [ 57, 49, 41, 33, 25, 17, 9,
				1, 58, 50, 42, 34, 26, 18,
				10, 2, 59, 51, 43, 35, 27,
				19, 11, 3, 60, 52, 44, 36 ];

const PC1_D = [ 63, 55, 47, 39, 31, 23, 15,
				7, 62, 54, 46, 38, 30, 22,
				14, 6, 61, 53, 45, 37, 29,
				21, 13, 5, 28, 20, 12, 4 ];

const SHIFTS = [ 1, 1, 2, 2, 2, 2, 2, 2,
				 1, 2, 2, 2, 2, 2, 2, 1 ];

const PC2_C = [ 14, 17, 11, 24, 1, 5,
				3, 28, 15, 6, 21, 10,
				23, 19, 12, 4, 26, 8,
				16, 7, 27, 20, 13, 2 ];

const PC2_D = [ 41, 52, 31, 37, 47, 55,
				30, 40, 51, 45, 33, 48,
				44, 49, 39, 56, 34, 53,
				46, 42, 50, 36, 29, 32 ];

const E = [ 32, 1, 2, 3, 4, 5,
			4, 5, 6, 7, 8, 9,
			8, 9, 10, 11, 12, 13,
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25,
			24, 25, 26, 27, 28, 29,
			28, 29, 30, 31, 32, 1 ];

const S = [	[ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
			  0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			  4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			  15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ],
			[ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
			  3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
			  0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
			  13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ],
			[ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
			  13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
			  13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
			  1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ],
			[ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
			  13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
			  10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
			  3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 ],
			[ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
			  14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
			  4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
			  11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ],
			[ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
			  10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
			  9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
			  4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ],
			[ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
			  13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
			  1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
			  6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ],
			[ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
			  1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
			  7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
			  2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 ] ];

const P	 = [ 16, 7, 20, 21,
			 29, 12, 28, 17,
			 1, 15, 23, 26,
			 5, 18, 31, 10,
			 2, 8, 24, 14,
			 32, 27, 3, 9,
			 19, 13, 30, 6,
			 22, 11, 4, 25 ];

function encrypt(block,  key)
{
	let L, R;
	{
		let perm = Buffer.alloc(64);
		for (let i = 0; i < 64; i++) {
			perm[i] = block[IP[i] - 1];
		}
		L = perm.slice(0, 32);
		R = perm.slice(32, 64);
	}
	let preS = Buffer.alloc(48);
	let f = Buffer.alloc(32);
	for (let i = 0; i < 16; i++) {
		let tempL = Buffer.from(R);
		for (let j = 0; j < 48; j++) {
			preS[j] = R[key.e[j] - 1] ^ key.ks[i][j];
		}
		for (let j = 0; j < 8; j++) {
			let t = 6 * j;
			let k = S[j][(preS[t + 0] << 5) +
						 (preS[t + 1] << 3) +
						 (preS[t + 2] << 2) +
						 (preS[t + 3] << 1) +
						 (preS[t + 4] << 0) +
						 (preS[t + 5] << 4)];
			t = 4 * j;
			f[t + 0] = (k >> 3) & 1;
			f[t + 1] = (k >> 2) & 1;
			f[t + 2] = (k >> 1) & 1;
			f[t + 3] = (k >> 0) & 1;
		}
		for (let j = 0; j < 32; j++) {
			R[j] = L[j] ^ f[P[j] - 1];
		}
		L = tempL;
	}
	let ret = Buffer.alloc(64);
	{
		let perm = Buffer.concat([R, L]);
		for (let i = 0; i < 64; i++) {
			ret[i] = perm[FP[i] - 1];
		}
	}
	return ret;
}

function mkKey(k) {
	let block = Buffer.alloc(64);
	for (let i = 0; (i < 8) && (i < k.length); i++) {
		for (let j = 0; j < 7; j++) {
			block[(i * 8) + j] = (k[i] >> (7 - j)) & 1;
		}
	}
	let C = Buffer.alloc(28);
	let D = Buffer.alloc(28);
	for (let i = 0; i < 28; i++) {
		C[i] = block[PC1_C[i] - 1];
		D[i] = block[PC1_D[i] - 1];
	}
	let ks = (new Array(16)).fill(0).map(function() { return Buffer.alloc(48); });
	for (let i = 0; i < 16; i++) {
		C = Buffer.concat([ C.slice(SHIFTS[i], C.length), C.slice(0, SHIFTS[i]) ]);
		D = Buffer.concat([ D.slice(SHIFTS[i], D.length), D.slice(0, SHIFTS[i]) ]);
		for (let j = 0; j < 24; j++) {
			ks[i][j] = C[PC2_C[j] - 1];
			ks[i][j + 24] = D[PC2_D[j] - 28 - 1];
		}
	}
	let e = Array.from(E);
	return {ks: ks, e: e};
}

function setKeySalt(key, sb) {
	let e = Array.from(E);
	for (let i = 0; i < sb.length; i++) {
		for (let j = 0; j < 6; j++) {
			if ((sb[i] >> j) & 1) {
				let t = e[(6 * i) + j];
				e[(6 * i) + j] = e[(6 * i) + j + 24];
				e[(6 * i) + j + 24] = t;
			}
		}
	}
	return {ks: key.ks, e: e};
}

function byteBufToBitBuf(b) {
	var r = Buffer.alloc(b.length << 3);
	for (let i = 0; i < b.length; i++) {
		for (let j = 0; j < 8; j++) {
			r[(i * 8) + j] = (b[i] >> (7 - j)) & 1;
		}
	}
	return r;
}

function bitBufToByteBuf(b) {
	var r = Buffer.alloc(b.length >> 3);
	for (let i = 0; i < r.length; i++) {
		for (let j = 0; j < 8; j++) {
			r[i] = (r[i] << 1) | b[(i * 8) + j];
		}
	}
	return r;
}

function crypt(password, salt) {
	var sb, pb, kb, rounds, key, block, r;
	if (typeof(password) !== 'string') {
		throw new TypeError('Password not a string');
	}
	if (typeof(salt) !== 'string') {
		throw new TypeError('Salt not a string');
	}
	if (salt.match(/^[./0-9A-Za-z]{2}/)) {
		rounds = 25;
		sb = Buffer.from([ pb64.c2n(salt.charAt(0)),
						   pb64.c2n(salt.charAt(1)) ]);
		pb = Buffer.from(password, 'utf8').slice(0, 8);
	} else if (salt.match(/^_[./0-9A-Za-z]{8}/)) {
		rounds = ((pb64.c2n(salt.charAt(1))) |
				  (pb64.c2n(salt.charAt(2)) << 6) |
				  (pb64.c2n(salt.charAt(3)) << 12) |
				  (pb64.c2n(salt.charAt(4)) << 18));
		sb = Buffer.from([ pb64.c2n(salt.charAt(5)),
						   pb64.c2n(salt.charAt(6)),
						   pb64.c2n(salt.charAt(7)),
						   pb64.c2n(salt.charAt(8)) ]);
		pb = Buffer.from(password, 'utf8');
	} else {
		throw new RangeError('Malformed salt');
	}
	for (let i = 0; i < pb.length; i++) {
		pb[i] <<= 1;
	}
	if (pb.length % 8) {
		pb = Buffer.concat([ pb, Buffer.alloc(8 - (pb.length % 8)) ]);
	}
	kb = Buffer.alloc(8);
	for (let i = 0; i < pb.length; i += 8) {
		if (i > 0) {
			kb = byteBufToBitBuf(kb);
			kb = encrypt(kb, key);
			kb = bitBufToByteBuf(kb)
		}
		for (let j = 0; j < 8; j++) {
			kb[j] ^= pb[i + j];
		}
		key = mkKey(kb);
	}
	key = setKeySalt(key, sb);
	block = Buffer.alloc(64);
	for (let i = 0; i < rounds; i++) {
		block = encrypt(block, key);
	}
	r = salt;
	for (let i = 0; i < 11; i++){
		let c = 0;
		for(let j = 0; j < 6; j++) {
			c <<= 1;
			c |= block[6 * i + j];
		}
		r += pb64.n2c(c);
	}
	return r;
}

module.exports = crypt;
