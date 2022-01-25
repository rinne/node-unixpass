'use strict';

const crypto = require('crypto');
const pb64 = require('./pb64.js');
const desCrypt = require('./pwdes.js');
const bcrypt = require('./bcrypt.js');

const UNIXPASS_CRYPT_STD_DES = 1;
const UNIXPASS_CRYPT_EXT_DES = 2;
const UNIXPASS_CRYPT_MD5 = 3;
const UNIXPASS_CRYPT_BLOWFISH = 4;
const UNIXPASS_CRYPT_SHA256 = 5;
const UNIXPASS_CRYPT_SHA512 = 6;

const VOC_ALPHANUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const VOC_PB64 = pb64.voc;

function rndInt(min, max) {
	if (! (Number.isSafeInteger(min) && Number.isSafeInteger(max))) {
		throw new TypeError('Non integer limits');
	}
	if ((min > max) || (min < -0xffffffff) || (max > 0x100000000)) {
		throw new RangeError('Unacceptable limits');
	}
	if (min == max) {
		return min;
	}
	let	b = crypto.randomBytes(7);
	let n = (b.readUIntLE(0, 6) + ((b.readUInt8(6) & 0x0f) * 0x1000000000000));
	return (n % (max - min)) + min;
}

function rndStr(len, voc) {
	var r, i;
	if (! (Number.isSafeInteger(len) && (typeof(voc) === 'string'))) {
		throw new TypeError('Bad length or vocabulary');
	}
	if (! (len >= 0) && (len <= 0x100000) && (voc.length > 0)) {
		throw new RangeError('Unacceptable length or vocabulary');
	}
	for (i = 0, r = ''; i < len; i++) {
		r += voc.charAt(rndInt(0, voc.length));
	}
	return r;
}

const hashCrypt = function(password, salt, alg, rounds, roundsExplicit) {
	var hn, hl, i, a, b, c, ar, br, cr, p, s, h, rv;
	switch (alg) {
	case 1:
		hn = 'md5';
		hl = 16;
		if (salt.length > 8) {
			salt = salt.slice(0, 8);
		}
		break;
	case 5:
		hn = 'sha256';
		hl = 32;
		if (salt.length > 16) {
			salt = salt.slice(0, 16);
		}
		break;
	case 6:
		hn = 'sha512';
		hl = 64;
		if (salt.length > 16) {
			salt = salt.slice(0, 16);
		}
		break;
	}
	try {
		a = crypto.createHash(hn);
		b = crypto.createHash(hn);
	} catch (e) {
		a = undefined;
	}
	if (a === undefined) {
		return false;
	}
	a.update(password);
	if (alg == 1) {
		a.update('$1$');
	}
	a.update(salt);
	b.update(password);
	b.update(salt);
	b.update(password);
	br = b.digest();
	b = undefined;
	for (i = password.length; i > hl; i -= hl) {
		a.update(br);
	}
	a.update(br.slice(0, i));
	for (i = password.length; i > 0; i >>= 1) {
		if (alg == 1) {
			// This is obviously a bug in the original implementation,
			// but we'll reproduce it in order to be compatible. There
			// isn't any real security implication because of this.
			if (i & 1) {
				a.update("\0");
			} else {
				a.update((password.length > 0) ? password.substr(0, 1) : "\0");
			}
		} else {
			if (i & 1) {
				a.update(br);
			} else {
				a.update(password);
			}
		}
	}
	ar = a.digest();
	a = undefined;
	switch (alg) {
	case 1:
		for (i = 0; i < rounds; i++) {
			a = crypto.createHash(hn);
			if (i & 1) {
				a.update(password);
			} else {
				a.update(ar);
			}
			if (i % 3) {
				a.update(salt);
			}
			if (i % 7) {
				a.update(password);
			}
			if (i & 1) {
				a.update(ar);
			} else {
				a.update(password);
			}
			ar = a.digest();
			a = undefined;
		}
		break;
	case 5:
	case 6:
		c = crypto.createHash(hn);
		for (i = password.length; i > 0; i--) {
			c.update(password);
		}
		cr = c.digest();
		c = undefined;
		p = Buffer.alloc(0);
		while (p.length < password.length) {
			p = Buffer.concat([ p, cr ]);
		}
		cr = undefined;
		if (p.length > password.length) {
			p = p.slice(0, password.length);
		}
		c = crypto.createHash(hn);
		for (i = 16 + ar[0]; i > 0; i--) {
			c.update(salt);
		}
		cr = c.digest();
		c = undefined;
		s = Buffer.alloc(0);
		while (s.length < salt.length) {
			s = Buffer.concat([ s, cr ]);
		}
		cr = undefined;
		if (s.length > salt.length) {
			s = s.slice(0, salt.length);
		}
		for (i = 0; i < rounds; i++) {
			a = crypto.createHash(hn);
			if (i & 1) {
				a.update(p);
			} else {
				a.update(ar);
			}
			if (i % 3) {
				a.update(s);
			}
			if (i % 7) {
				a.update(p);
			}
			if (i & 1) {
				a.update(ar);
			} else {
				a.update(p);
			}
			ar = a.digest();
			a = undefined;
		}
		break;
	}
	switch (alg) {
	case 1:
		// What did they smoke, when they came up with this?
		h = (pb64.encb(ar[0], ar[6], ar[12], 4) +
			 pb64.encb(ar[1], ar[7], ar[13], 4) +
			 pb64.encb(ar[2], ar[8], ar[14], 4) +
			 pb64.encb(ar[3], ar[9], ar[15], 4) +
			 pb64.encb(ar[4], ar[10], ar[5], 4) +
			 pb64.encb(0, 0, ar[11], 2));
		break;
	case 5:
		// What did they smoke, when they came up with this?
		h = (pb64.encb(ar[0], ar[10], ar[20], 4) +
			 pb64.encb(ar[21], ar[1], ar[11], 4) +
			 pb64.encb(ar[12], ar[22], ar[2], 4) +
			 pb64.encb(ar[3], ar[13], ar[23], 4) +
			 pb64.encb(ar[24], ar[4], ar[14], 4) +
			 pb64.encb(ar[15], ar[25], ar[5], 4) +
			 pb64.encb(ar[6], ar[16], ar[26], 4) +
			 pb64.encb(ar[27], ar[7], ar[17], 4) +
			 pb64.encb(ar[18], ar[28], ar[8], 4) +
			 pb64.encb(ar[9], ar[19], ar[29], 4) +
			 pb64.encb(0, ar[31], ar[30], 3));
		break;
	case 6:
		// What did they smoke, when they came up with this?
		h = (pb64.encb(ar[0], ar[21], ar[42], 4) +
			 pb64.encb(ar[22], ar[43], ar[1], 4) +
			 pb64.encb(ar[44], ar[2], ar[23], 4) +
			 pb64.encb(ar[3], ar[24], ar[45], 4) +
			 pb64.encb(ar[25], ar[46], ar[4], 4) +
			 pb64.encb(ar[47], ar[5], ar[26], 4) +
			 pb64.encb(ar[6], ar[27], ar[48], 4) +
			 pb64.encb(ar[28], ar[49], ar[7], 4) +
			 pb64.encb(ar[50], ar[8], ar[29], 4) +
			 pb64.encb(ar[9], ar[30], ar[51], 4) +
			 pb64.encb(ar[31], ar[52], ar[10], 4) +
			 pb64.encb(ar[53], ar[11], ar[32], 4) +
			 pb64.encb(ar[12], ar[33], ar[54], 4) +
			 pb64.encb(ar[34], ar[55], ar[13], 4) +
			 pb64.encb(ar[56], ar[14], ar[35], 4) +
			 pb64.encb(ar[15], ar[36], ar[57], 4) +
			 pb64.encb(ar[37], ar[58], ar[16], 4) +
			 pb64.encb(ar[59], ar[17], ar[38], 4) +
			 pb64.encb(ar[18], ar[39], ar[60], 4) +
			 pb64.encb(ar[40], ar[61], ar[19], 4) +
			 pb64.encb(ar[62], ar[20], ar[41], 4) +
			 pb64.encb(0, 0, ar[63], 2));
		break;
	}
	rv = '$' + alg.toString() + '$' + (roundsExplicit ? ('rounds=' + rounds.toString() + '$') : '') + salt + '$' + h;
	return rv;
};

const crypt = function(password, salt) {
	var m, rounds;
	if (! ((typeof(password) === 'string') && (typeof(salt) === 'string'))) {
		return false;
	}
	if (salt.match(/^([\.\/0-9A-Za-z]{2})([\.\/0-9A-Za-z]{11})?$/) ||
		salt.match(/^_([\.\/0-9A-Za-z]{4})([\.\/0-9A-Za-z]{4})([\.\/0-9A-Za-z]{11})?$/)) {		
		let r;
		try {
			r = desCrypt(password, salt);
		} catch (e) {
			console.log(e);
			r = false;
		}
		return r;
	}
	m = salt.match(/^((\$([156])\$)(rounds=([1-9][0-9]{0,13})\$)?)([^\$]+)(\$([\.\/0-9A-Za-z]*)?)?$/);
	if (m) {
		// We deviate a little from the original MD5 password hashing,
		// since it doesn't allow explicitly given number of
		// rounds. If in the original implementation, rounds are given
		// explicitly, the salt becomes "rounds=#" where # is the
		// first digit of the number of rounds. This is already so
		// brain damaged, that we'll just ignore it.
		var alg = Number.parseInt(m[3]);
		rounds = Math.max(1000, Math.min(999999999, (m[5] === undefined) ? ((alg == 1) ? 1000 : 5000) : Number.parseInt(m[5])));
		salt = m[6];
		return hashCrypt(password, salt, alg, rounds, (m[4] !== undefined));
	}
	m = salt.match(/^(\$2([abxy]|)\$(\d\d)\$)([./0-9A-Za-z]{22})/);
	if (m) {
		return bcrypt(password, salt);
	}
	return false;
};

var mksalt = function(type) {
	var r, n, b;
	switch (type) {
	case UNIXPASS_CRYPT_STD_DES:
		r = rndStr(2, VOC_PB64);
		break;
	case UNIXPASS_CRYPT_EXT_DES:
		n = rndInt(1024, 1280) | 1;
		r = ('_' +
			 pb64.n2c(n & 0x3f) + pb64.n2c((n >> 6) & 0x3f) +
			 pb64.n2c((n >> 12) & 0x3f) + pb64.n2c((n >> 18) & 0x3f) +
			 rndStr(4, VOC_PB64));
		break;
	case UNIXPASS_CRYPT_MD5:
		r = '$1$' + rndStr(8, VOC_ALPHANUM) + '$';
		break;
	case UNIXPASS_CRYPT_BLOWFISH:
		r = '$2a$11$' + rndStr(21, VOC_ALPHANUM) + 'z';
		break;
	case UNIXPASS_CRYPT_SHA256:
		r = '$5$rounds=' + rndInt(5000, 6000).toString() + '$' + rndStr(16, VOC_ALPHANUM) + '$';
		break;
	case UNIXPASS_CRYPT_SHA512:
		r = '$6$rounds=' + rndInt(5000, 6000).toString() + '$' + rndStr(16, VOC_ALPHANUM) + '$';
		break;
	default:
		throw new RangeError('Unsupported password type');
	}
	return r;
}

var mkpass = function(password, type) {
	if (! type) {
		type = UNIXPASS_CRYPT_SHA512;
	}
	var salt = mksalt(type);
	var r = crypt(password, salt);
	return r;
};

var check = function(password, hash) {
	if (! ((typeof(password) === 'string') && (typeof(hash) === 'string'))) {
		return false;
	}
	var hash2 = crypt(password, hash);
	return hash2 && hash2.length && (hash2 === hash);
}

module.exports = {
	crypt: crypt,
	mkpass: mkpass,
	check: check,
	UNIXPASS_CRYPT_STD_DES: UNIXPASS_CRYPT_STD_DES,
	UNIXPASS_CRYPT_EXT_DES: UNIXPASS_CRYPT_EXT_DES,
	UNIXPASS_CRYPT_MD5: UNIXPASS_CRYPT_MD5,
	UNIXPASS_CRYPT_BLOWFISH: UNIXPASS_CRYPT_BLOWFISH,
	UNIXPASS_CRYPT_SHA256: UNIXPASS_CRYPT_SHA256,
	UNIXPASS_CRYPT_SHA512: UNIXPASS_CRYPT_SHA512
};
