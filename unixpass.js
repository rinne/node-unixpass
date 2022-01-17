'use strict';

const createHash = require('crypto').createHash;
const pb64 = require('./pb64.js');
const desCrypt = require('./pwdes.js');

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
		a = createHash(hn);
		b = createHash(hn);
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
			a = createHash(hn);
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
		c = createHash(hn);
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
		c = createHash(hn);
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
			a = createHash(hn);
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

const bfCrypt = function(password, salt, alg, cost) {
	if (! ((typeof(password) === 'string') && (typeof(salt) === 'string') &&
		   Number.isInteger(cost) && (cost > 0) && (cost < 100) &&
		   ([ '2', '2a', '2b', '2x', '2y' ].indexOf(alg) >= 0))) {
		return false;
	}
	// Not implemented. Sorry.
	return false;
}

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
	m = salt.match(/^\$(2[abxy]?)\$([0-9]{2})\$([\.\/0-9A-Za-z]{22})([\.\/0-9A-Za-z]{31})?$/);
	if (m) {
		var alg = m[1];
		rounds = Number.parseInt(m[2]);
		salt = m[3];
		return bfCrypt(password, salt, alg, rounds)
	}
	return false;
};

var mkpass = function(password) {
	const sv = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
	var i, salt = ('$6$rounds=' + (5500 + Math.trunc((Math.random() * 500))).toFixed(0) + '$');
	for (i = 0; i < 16; i++) {
		salt += sv.substr(Math.trunc((Math.random() * sv.length)), 1);
	}
	return crypt(password, salt);
};

var check = function(password, hash) {
	if (! ((typeof(password) === 'string') && (typeof(hash) === 'string'))) {
		return false;
	}
	var hash2 = crypt(password, hash);
	return hash2 === hash;
}

module.exports = {
	crypt: crypt,
	mkpass: mkpass,
	check: check
};
