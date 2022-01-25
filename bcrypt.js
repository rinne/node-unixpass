'use stict';

const blf = require('blowfish-js');
const bc64 = require('./pb64.js').bc;

function bcrypt(password, salt) {
	var r;
	try {
		let cdata = Buffer.from('OrpheanBeholderScryDoubt');
		if (typeof(password) !== 'string') {
			throw new TypeError('Password not a string');
		}
		if (typeof(salt) !== 'string') {
			throw new TypeError('Salt not a string');
		}
		let m = salt.match(/^(\$2([abxy]|)\$(\d\d)\$)([./0-9A-Za-z]{22})/);
		if (! m) {
			throw new RangeError('Malformed salt');
		}
		let variant = m[2];
		let cost = Number.parseInt(m[3], 10);
		if ((cost === undefined) ||
			(cost === null) ||
			(cost < 4) ||
			(cost > 30)) {
			throw new RangeError('Invalid cost');
		}
		let rounds = 1 << cost;
		let passbuf = Buffer.from((password + '\0').slice(0, 72), 'utf8');
		let salthead = m[1];
		let saltbuf = bc64.dec(m[4]);
		let cipher = blf.allocState();
		cipher = blf.expandState(cipher, passbuf, saltbuf);
		for (let i = 0; i < rounds; i++) {
			cipher = blf.expandState(cipher, passbuf);
			cipher = blf.expandState(cipher, saltbuf);
		}
		if (cdata.length != 24) {
			throw new Error('Unexpected plaintext length');
		}
		for (let i = 0; i < 64; i++) {
			cdata = blf.ecb(cipher, cdata);
		}
		if (cdata.length != 24) {
			throw new Error('Unexpected ciphertext length');
		}
		cdata = cdata.slice(0, 23);
		r = salthead + bc64.enc(saltbuf) + bc64.enc(cdata);
	} catch (e) {
		console.log(e);
		r = undefined;
		throw new Error('Password hash error');
	}
	return r;
}

module.exports = bcrypt;
