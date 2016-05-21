'use strict';

const up = require('../unixpass.js');

const test = function() {
	const t = [
		// The following test vectors are from reference implementation.
		{ p: "Hello world!",
		  s: "$1$saltstring",
		  r: "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1" },
		{ p: "Hello world!",
		  s: "$5$saltstring",
		  r: "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },
		{ p: "Hello world!",
		  s: "$5$rounds=10000$saltstringsaltstring",
		  r: "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA" },
		{ p: "This is just a test",
		  s: "$5$rounds=5000$toolongsaltstring",
		  r: "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5" },
		{ p: "a very much longer text to encrypt.  This one even stretches over morethan one line.",
		  s: "$5$rounds=1400$anotherlongsaltstring",
		  r: "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1" },
		{ p: "we have a short salt string but not a short password",
		  s: "$5$rounds=77777$short",
		  r: "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/" },
		{ p: "a short string",
		  s: "$5$rounds=123456$asaltof16chars..",
		  r: "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD" },
		{ p: "the minimum number is still observed",
		  s: "$5$rounds=10$roundstoolow",
		  r: "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC" },
		{ p: "Hello world!",
		  s: "$6$saltstring",
		  r: "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1" },
		{ p: "Hello world!",
		  s: "$6$rounds=10000$saltstringsaltstring",
		  r: "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v." },
		{ p: "This is just a test",
		  s: "$6$rounds=5000$toolongsaltstring",
		  r: "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0" },
		{ p: "a very much longer text to encrypt.  This one even stretches over morethan one line.",
		  s: "$6$rounds=1400$anotherlongsaltstring",
		  r: "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1" },
		{ p: "we have a short salt string but not a short password",
		  s: "$6$rounds=77777$short",
		  r: "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0" },
		{ p: "a short string",
		  s: "$6$rounds=123456$asaltof16chars..",
		  r: "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1" },
		{ p: "the minimum number is still observed",
		  s: "$6$rounds=10$roundstoolow",
		  r: "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX." },
		// The rest are not official test vectors but are generated
		// using GNU libc implementation, because there was only one
		// test for MD5 based password hash.
		{ p: "Hello world!",
		  s: "$1$toolongsaltistruncated",
		  r: "$1$toolongs$EVlrXgIzSyVBiscgwJ6jL0" },
		{ p: "a very much longer text to encrypt.  This one even stretches over morethan one line.",
		  s: "$1$anotherlongsaltstring",
		  r: "$1$anotherl$K6Vw1g4o5xCrk48TD5civ." }
	];
	var n = 0, ok = 0;

	t.forEach(function(t) {
		var r = up.crypt(t.p, t.s);
		n++;
		if (r === t.r) {
			console.log('#' + n.toString() + ' OK');
			ok++;
		} else {
			console.log('#' + n.toString() + ' FAIL!');
			console.log("  crypt(\"" + t.p + "\", \"" + t.s + "\") -> \"" + r + "\"");
			console.log("  expected \"" + t.r + "\"");
		}
	});
	if (ok != n) {
		console.log(ok.toString() + '/' + n.toString() + " tests OK. " + (n - ok).toString() + " tests failed.");
		return false;
	}
	console.log("All " + n.toString() + " tests OK.");
	return true;
};

process.exit(test() ? 0 : 1);

