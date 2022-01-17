'use strict';

const pb64voc = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

const c2n = function(c) {
	 let r = pb64voc.indexOf(c);
	 return (r >= 0) ? r : undefined;
}

const n2c = function(n) {
	 if (! (Number.isSafeInteger(n) && (n >= 0) && (n < pb64voc.length))) {
	    return undefined;
	 }
	 return pb64voc.charAt(n);
}

const encb = function(b0, b1, b2, rl) {
	var rv = '';
	for (let n = ((b0 & 0xff) << 16) | ((b1 & 0xff) << 8) | (b2 & 0xff); rv.length < rl; n >>= 6) {
		rv += n2c(n & 0x3f);
	}
	return rv;
};

module.exports = {
	voc: pb64voc,
	c2n: c2n,
	n2c: n2c,
	encb: encb
};
