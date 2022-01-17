'use strict';

const pb64voc = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

const pb64 = function(b0, b1, b2, rl) {
	var rv = '', n;
	for (n = ((b0 & 0xff) << 16) | ((b1 & 0xff) << 8) | (b2 & 0xff); rv.length < rl; n >>= 6) {
		rv += pb64voc.substr(n & 0x3f, 1);
	}
	return rv;
};

const pb64d = function(s) {
	var a, b, c, d, rv = Buffer.alloc(0), tb;
	if (! (typeof(s) === 'string')) {
		return false;
	}
	while (s.length >= 2) {
		switch (s.length) {
		case 2:
			a = pb64voc.indexOf(s.substr(0, 1));
			b = pb64voc.indexOf(s.substr(1, 1));
			if (! ((a >= 0) && (b >= 0) && ((b & 0xf) == 0))) {
				return false;
			}
			s = '';
			tb = Buffer.from([ (a << 2) | (b >> 4) ]);
			break;
		case 3:
			a = pb64voc.indexOf(s.substr(0, 1));
			b = pb64voc.indexOf(s.substr(1, 1));
			c = pb64voc.indexOf(s.substr(2, 1));
			if (! ((a >= 0) && (b >= 0) && (c >= 0) && ((c & 0x3) == 0))) {
				return false;
			}
			s = '';
			tb = Buffer.from([ (a << 2) | (b >> 4), ((b & 0xf) << 4) | (c >> 2) ]);
			break;
		default:
			a = pb64voc.indexOf(s.substr(0, 1));
			b = pb64voc.indexOf(s.substr(1, 1));
			c = pb64voc.indexOf(s.substr(2, 1));
			d = pb64voc.indexOf(s.substr(3, 1));
			if (! ((a >= 0) && (b >= 0) && (c >= 0) && (d >= 0))) {
				return false;
			}
			s = s.substr(4);
			tb = Buffer.from([ (a << 2) | (b >> 4), ((b & 0xf) << 4) | (c >> 2), ((c & 0x3) << 6) | d ]);
			break;
		}
		rv = Buffer.concat([ rv, tb ]);
	}
	if (s.length > 0) {
		return false;
	}
	return rv;
};

module.exports = {
	enc: pb64,
	dec: pb64d,
	voc: pb64voc
};
