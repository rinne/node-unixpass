'use strict';

const crypto = require('crypto');
const pb64 = require('./pb64.js');
const desCrypt = require('./pwdes.js');
const bcrypt = require('./bcrypt.js');
const hashCrypt = require('./hash-crypt.js');

const UNIXPASS_CRYPT_STD_DES = 1;
const UNIXPASS_CRYPT_EXT_DES = 2;
const UNIXPASS_CRYPT_MD5 = 3;
const UNIXPASS_CRYPT_BCRYPT = 4;
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

const crypt = function(password, salt) {
	var m;
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
		let r;
		try {
			let alg = Number.parseInt(m[3]);
			let rounds = Math.max(1000, Math.min(999999999, (m[5] === undefined) ? ((alg == 1) ? 1000 : 5000) : Number.parseInt(m[5])));
			let salt = m[6];
			r = hashCrypt(password, salt, alg, rounds, (m[4] !== undefined));
		} catch (e) {
			console.log(e);
			r = false;
		}
		return r;
	}
	m = salt.match(/^(\$2([abxy]|)\$(\d\d)\$)([./0-9A-Za-z]{22})/);
	if (m) {
		let r;
		try {
			r = bcrypt(password, salt);
		} catch (e) {
			console.log(e);
			r = false;
		}
		return r;
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
	case UNIXPASS_CRYPT_BCRYPT:
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
	UNIXPASS_CRYPT_BCRYPT: UNIXPASS_CRYPT_BCRYPT,
	UNIXPASS_CRYPT_SHA256: UNIXPASS_CRYPT_SHA256,
	UNIXPASS_CRYPT_SHA512: UNIXPASS_CRYPT_SHA512
};
