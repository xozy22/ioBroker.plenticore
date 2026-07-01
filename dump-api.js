'use strict';

/*
 * Standalone KOSTAL Plenticore API Dumper
 * ---------------------------------------
 * Meldet sich mit der gleichen Logik wie der ioBroker-Adapter an der internen
 * REST-API an und schreibt ALLE verfügbaren Module, processdata-IDs (inkl.
 * aktueller Werte) und Settings in die Datei kostal-dump.json.
 *
 * Aufruf (PowerShell / cmd), im Ordner ioBroker.plenticore:
 *   node dump-api.js <IP> <PASSWORT> [PORT] [http|https]
 * Beispiel:
 *   node dump-api.js 192.168.0.23 meinPasswort 80 http
 *
 * Alternativ über Umgebungsvariablen:
 *   KOSTAL_IP, KOSTAL_PW, KOSTAL_PORT (default 80), KOSTAL_PROTO (default http)
 *
 * Es werden KEINE Werte geschrieben/verändert, nur gelesen.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const KOSTAL = require('./lib/kostal').KOSTAL;

const apiurl = '/api/v1/';

const argv = process.argv.slice(2);
const deviceIp = argv[0] || process.env.KOSTAL_IP;
const devicePassword = argv[1] || process.env.KOSTAL_PW;
const devicePort = parseInt(argv[2] || process.env.KOSTAL_PORT || '80', 10);
const proto = (argv[3] || process.env.KOSTAL_PROTO || 'http').toLowerCase();
const deviceHttps = proto === 'https';

if (!deviceIp || !devicePassword) {
	console.error('Fehlende Angaben.\nAufruf: node dump-api.js <IP> <PASSWORT> [PORT] [http|https]');
	process.exit(1);
}

let loginSessionId = null;

function apiCall(method, endpoint, data) {
	return new Promise((resolve, reject) => {
		method = method.toUpperCase();
		if (data !== null && typeof data !== 'string') {
			data = JSON.stringify(data);
		}
		const headers = {
			'User-Agent': 'KostalDumper/1.0'
		};
		if (data) {
			headers['Content-Type'] = 'application/json';
		}
		if (loginSessionId) {
			headers['Authorization'] = 'Session ' + loginSessionId;
		}
		const reqOpts = {
			method: method,
			port: devicePort,
			host: deviceIp,
			path: apiurl + endpoint,
			headers: headers,
			rejectUnauthorized: false
		};
		const lib = deviceHttps ? https : http;
		const request = lib.request(reqOpts);
		request.on('response', (response) => {
			const code = response.statusCode;
			response.setEncoding('utf8');
			let body = '';
			response.on('data', (chunk) => { body += chunk; });
			response.on('end', () => resolve({ code, body }));
		});
		request.on('error', (err) => reject(err));
		if (data && (method === 'POST' || method === 'PUT')) {
			request.write(data);
		}
		request.end();
	});
}

async function login() {
	const nonce = KOSTAL.getNonce();
	let res = await apiCall('POST', 'auth/start', { username: 'user', nonce: nonce });
	if (res.code !== 200) throw new Error('auth/start fehlgeschlagen (' + res.code + '): ' + res.body);
	const json = JSON.parse(res.body);

	const mainTransactionId = json.transactionId;
	const serverNonce = json.nonce;
	const salt = json.salt;
	const hashRounds = parseInt(json.rounds);

	const r = KOSTAL.pbkdf2(devicePassword, KOSTAL.base64.toBits(salt), hashRounds);
	const sKey = new KOSTAL.hash.hmac(r, KOSTAL.hash.sha256).mac('Client Key');
	const cKey = new KOSTAL.hash.hmac(r, KOSTAL.hash.sha256).mac('Server Key');
	const sHash = KOSTAL.hash.sha256.hash(sKey);
	const hashString = 'n=user,r=' + nonce + ',r=' + serverNonce + ',s=' + salt + ',i=' + hashRounds + ',c=biws,r=' + serverNonce;
	const sHmac = new KOSTAL.hash.hmac(sHash, KOSTAL.hash.sha256).mac(hashString);
	const cHmac = new KOSTAL.hash.hmac(cKey, KOSTAL.hash.sha256).mac(hashString);
	const proof = sKey.map((l, n) => l ^ sHmac[n]);

	res = await apiCall('POST', 'auth/finish', {
		transactionId: mainTransactionId,
		proof: KOSTAL.base64.fromBits(proof)
	});
	if (res.code !== 200) throw new Error('auth/finish fehlgeschlagen (' + res.code + '): ' + res.body);
	const json2 = JSON.parse(res.body);

	const bitSignature = KOSTAL.base64.toBits(json2.signature);
	if (!KOSTAL.bitArray.equal(bitSignature, cHmac)) {
		throw new Error('Signaturprüfung fehlgeschlagen (falsches Passwort?)');
	}

	const hashHmac = new KOSTAL.hash.hmac(sHash, KOSTAL.hash.sha256);
	hashHmac.update('Session Key');
	hashHmac.update(hashString);
	hashHmac.update(sKey);
	const protocol_key = hashHmac.digest();

	const encToken = KOSTAL.encrypt(protocol_key, json2.token);
	res = await apiCall('POST', 'auth/create_session', {
		transactionId: mainTransactionId,
		iv: KOSTAL.base64.fromBits(encToken.iv),
		tag: KOSTAL.base64.fromBits(encToken.tag),
		payload: KOSTAL.base64.fromBits(encToken.ciphertext)
	});
	if (res.code !== 200) throw new Error('auth/create_session fehlgeschlagen (' + res.code + '): ' + res.body);
	const json3 = JSON.parse(res.body);
	if (!json3.sessionId) throw new Error('Keine sessionId erhalten: ' + res.body);
	loginSessionId = json3.sessionId;
}

async function main() {
	console.log('Login bei ' + deviceIp + ':' + devicePort + ' (' + proto + ') ...');
	await login();
	console.log('Login erfolgreich.\n');

	const out = {};

	// 1) Modulliste
	let res = await apiCall('GET', 'modules', null);
	out.modules = safeParse(res.body);

	// 2) Alle verfügbaren processdata-IDs je Modul (Liste ohne Werte)
	res = await apiCall('GET', 'processdata', null);
	const processdataList = safeParse(res.body);
	out.processdata_available = processdataList;

	// 3) Aktuelle Werte für ALLE processdata-IDs je Modul abfragen
	out.processdata_values = [];
	if (Array.isArray(processdataList)) {
		for (const mod of processdataList) {
			if (!mod.moduleid || !Array.isArray(mod.processdataids)) continue;
			const payload = [{ moduleid: mod.moduleid, processdataids: mod.processdataids }];
			const r = await apiCall('POST', 'processdata', payload);
			out.processdata_values.push({ moduleid: mod.moduleid, code: r.code, data: safeParse(r.body) });
			console.log('processdata: ' + mod.moduleid + ' (' + mod.processdataids.length + ' Werte, HTTP ' + r.code + ')');
		}
	}

	// 4) Alle Settings je Modul (Liste + Werte)
	res = await apiCall('GET', 'settings', null);
	out.settings = safeParse(res.body);

	fs.writeFileSync('kostal-dump.json', JSON.stringify(out, null, 2));
	console.log('\nFertig. Alles gespeichert in: kostal-dump.json');
	console.log('Bitte diese Datei (oder ihren Inhalt) hier einfügen.');
}

function safeParse(s) {
	try { return JSON.parse(s); } catch (e) { return { _raw: s }; }
}

main().catch((err) => {
	console.error('FEHLER: ' + err.message);
	process.exit(1);
});
