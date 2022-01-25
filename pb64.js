'use strict';

const pb64voc = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const bc64voc = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

const c2n = function(voc, c) {
	 let r = voc.indexOf(c);
	 return (r >= 0) ? r : undefined;
}

const n2c = function(voc, n) {
	 if (! (Number.isSafeInteger(n) && (n >= 0) && (n < voc.length))) {
	    return undefined;
	 }
	 return voc.charAt(n);
}

const encb = function(voc, b0, b1, b2, rl) {
	var rv = '';
	for (let n = ((b0 & 0xff) << 16) | ((b1 & 0xff) << 8) | (b2 & 0xff); rv.length < rl; n >>= 6) {
		rv += n2c(voc, n & 0x3f);
	}
	return rv;
};

function dec(voc, s) {
	var a = [];
	if (typeof(s) !== 'string') {
		throw new TYpeError('Invalid bc64 input');
	}
	for (let i = 0; i < s.length; i += 4) {
		switch (Math.min(4, s.length - i)) {
		case 1:
			throw new RangeError('Invalid bc64 input length');
			/*NOTREACHED*/
		case 2:
			{
				let n1 = c2n(voc, s[i]);
				if (n1 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n2 = c2n(voc, s[i + 1]);
				if (n2 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n = (n1 << 2) | (n2 >>> 4);
				a.push(n);
			}
			break;
		case 3:
			{
				let n1 = c2n(voc, s[i]);
				if (n1 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n2 = c2n(voc, s[i + 1]);
				if (n2 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n3 = c2n(voc, s[i + 2]);
				if (n3 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n = (n1 << 10) | (n2 << 4) | (n3 >> 2);
				a.push(n >>> 8);
				a.push(n & 255);
			}
			break;
		case 4:
			{
				let n1 = c2n(voc, s[i]);
				if (n1 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n2 = c2n(voc, s[i + 1]);
				if (n2 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n3 = c2n(voc, s[i + 2]);
				if (n3 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n4 = c2n(voc, s[i + 3]);
				if (n4 === undefined) {
					throw new RangeError('Invalid bc64 input');
				}
				let n = (n1 << 18) | (n2 << 12) | (n3 << 6) | n4;
				a.push(n >>> 16);
				a.push((n >>> 8) & 255);
				a.push(n & 255);
			}
			break;
		}
	}
	return Buffer.from(a);
}

function enc(voc, b) {
	var r = '';
	if (! Buffer.isBuffer(b)) {
		throw new TYpeError('Invalid input');
	}
	for (let i = 0; i < b.length; i += 3) {
		switch (Math.min(3, b.length - i)) {
		case 1:
			{
				let n = b[i];
				r += n2c(voc, n >>> 2) + n2c(voc, (n << 4) & 63);
			}
			break;
		case 2:
			{
				let n = (b[i] << 8) | b[i + 1];
				r += n2c(voc, n >>> 10) + n2c(voc, (n >>> 4) & 63) + n2c(voc, (n << 2) & 63);
			}
			break;
		case 3:
			{
				let n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
				r += (n2c(voc, n >>> 18) +
					  n2c(voc, (n >>> 12) & 63) +
					  n2c(voc, (n >>> 6) & 63) +
					  n2c(voc, n & 63));
			}
			break;
		}
	}
	return r;
}


module.exports = {
	voc: pb64voc,
	c2n: (c => c2n(pb64voc, c)),
	n2c: (n => n2c(pb64voc, n)),
	encb: ((b0, b1, b2, rl) => encb(pb64voc, b0, b1, b2, rl)),
	dec: ((s) => dec(pb64voc, s)),
	enc: ((b) => enc(pb64voc, b)),
	bc: {
		voc: bc64voc,
		c2n: (c => c2n(bc64voc, c)),
		n2c: (n => n2c(bc64voc, n)),
		encb: ((b0, b1, b2, rl) => encb(bc64voc, b0, b1, b2, rl)),
		dec: ((s) => dec(bc64voc, s)),
		enc: ((b) => enc(bc64voc, b))
	}
};
