#!/usr/bin/env node
//@ts-check
import * as hex from "@dwbinns/base/hex";
import { yellow } from '@dwbinns/terminal/colour';
import tree from "@dwbinns/terminal/tree";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { Certificate, CertificationRequest, Extension, GeneralName, Name } from 'x509-io';
import * as x690 from "x690-io";
import { Pem } from 'x690-io';
import PublicKey from './src/asn1types/certificate/PublicKey.js';
import TBSCertificate from './src/asn1types/certificate/TBSCertificate.js';
import Validity from './src/asn1types/certificate/Validity.js';
import AuthorityKeyIdentifier from './src/asn1types/extensions/AuthorityKeyIdentifier.js';
import KeyUsage from './src/asn1types/extensions/KeyUsage.js';
import SubjectKeyIdentifier from './src/asn1types/extensions/SubjectKeyIdentifier.js';
import ECPrivateKey from './src/asn1types/key/ECPrivateKey.js';
import PKCS8PrivateKeyInfo from './src/asn1types/key/PKCS8PrivateKeyInfo.js';
import AlgorithmIdentifier from "./src/asn1types/certificate/AlgorithmIdentifier.js";
import https from 'node:https';
import { once } from "node:events";
import SubjectAltName from "./src/asn1types/extensions/SubjectAltName.js";
import BasicConstraints from "./src/asn1types/extensions/BasicConstraints.js";
import ExtendedKeyUsage from "./src/asn1types/extensions/ExtendedKeyUsage.js";
import { join } from "node:path";
import { concatBytes } from "buffer-io";

function children(object, prototype = object) {
    if (object instanceof Array) return [...object.entries()];
    if (!prototype || prototype == Object.prototype) return [];
    return [
        ...Object.getOwnPropertyNames(prototype)
            .map(name => [name, Object.getOwnPropertyDescriptor(prototype, name)])
            .filter(([, descriptor]) => descriptor.get || (descriptor.value != undefined && typeof descriptor.value != "function"))
            .map(([name]) => [name, object[name]]),
        ...children(object, Object.getPrototypeOf(prototype))
    ];
    //return [...Object.entries(object), ...Object.getOwnPropertyDescriptors(Object.getPrototypeOf(object)).map(name => [name, object[name]])];
}

function objectTree(name, object) {
    return tree({
        node: [name, object],
        getDescription: ([name, object]) => {
            let summary = "";
            if (!object || typeof object != "object") summary = `${object}`
            else if (object?.getDescription) summary = object.getDescription();
            else if (object instanceof Uint8Array) summary = hex.encode(object);
            else if (object instanceof Date) summary = object.toISOString();
            else summary = object.constructor?.name || "{}";
            return `${yellow(name)}: ${summary}`;
        },
        getChildren: ([, object], path) => {
            if (object?.getChildren) return object.getChildren();
            if (path.includes(object) || object instanceof Uint8Array) return [];
            if (object && typeof object == "object") return children(object).filter(([, value]) => value !== undefined);
            return [];
        },
    });
}

const types = [Certificate, CertificationRequest, PublicKey, ECPrivateKey, PKCS8PrivateKeyInfo];
const typeLookup = new Map(types.map(type => [type[x690.name], type]));

async function show(input) {
    for (let section of Pem.read(await readFile(input, { encoding: 'utf8' })).sections) {
        console.log(section.type);
        console.log(objectTree(section.type, section.decodeContent(typeLookup.get(section.type))));
    }
}

const generateParams = {
    rsa4096: {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    secp256r1: {
        name: "ECDSA",
        namedCurve: "P-256"
    },
};

async function writePem(pem, output) {
    if (output) await writeFile(output, pem.write());
    else console.log(pem.write());
}

async function loadPrivateKey(file) {
    return Pem.read(await readFile(file, { encoding: "utf8" })).findSection(PKCS8PrivateKeyInfo).content;
}

const importParams = {
    '1.2.840.113549.1.1.1': {
        name: 'RSASSA-PKCS1-v1_5',
    },
    '1.2.840.10045.3.1.7': {
        name: "ECDSA",
        namedCurve: "P-256",
    }
};

const ECDSA = "ECDSA";
const RSA = 'RSASSA-PKCS1-v1_5';
const SHA256 = "SHA-256";
const SHA512 = "SHA-512";

const signatureIDs = [
    { hash: SHA256, algorithm: ECDSA, id: AlgorithmIdentifier.ecdsaWithSha256 },
    { hash: SHA512, algorithm: ECDSA, id: AlgorithmIdentifier.ecdsaWithSha512 },
    { hash: SHA256, algorithm: RSA, id: AlgorithmIdentifier.rsaWithSha256 },
    { hash: SHA512, algorithm: RSA, id: AlgorithmIdentifier.rsaWithSha512 },
];


async function importPrivateKey(algorithm, bytes, hash) {
    const importOID = algorithm.parameters?.id || algorithm.algorithm.id;
    const params = importParams[importOID];

    return await crypto.subtle.importKey("pkcs8", bytes, { ...params, hash }, true, ["sign"]);
}


function parseInterval(interval, start = new Date()) {
    const [, count, unit] = interval.match(/^([0-9]*)([a-zA-Z])$/);
    return add(start, unit, Number(count || "1"));
}

async function generate(type, hash, output, authority, subject, usages, validity, ...dnsNames) {
    let params = generateParams[type];
    if (!params) {
        throw "Unknown key type";
    }

    const selfSigned = authority == "-";

    await mkdir(output);

    const keyPair = await crypto.subtle.generateKey({ ...generateParams[type], hash }, true, ["sign"]);

    const publicKeyData = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKeyData = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    const publicKeyPem = new Pem();
    publicKeyPem.addSection(PublicKey[x690.name], publicKeyData);
    await writePem(publicKeyPem, join(output, "publicKey.pem"));

    const keyIdentifier = await crypto.subtle.digest("SHA-256", publicKeyData);

    const privateKeyPem = new Pem();
    privateKeyPem.addSection(PKCS8PrivateKeyInfo[x690.name], privateKeyData);
    await writePem(privateKeyPem, join(output, "privateKey.pem"));

    const issuerPrivateKeyData = selfSigned ? privateKeyData : await loadPrivateKey(join(authority, "privateKey.pem"));

    const issuerPrivateKeyInfo = x690.decode(issuerPrivateKeyData, PKCS8PrivateKeyInfo);

    const issuerPrivateKey = selfSigned
        ? keyPair.privateKey
        : await importPrivateKey(issuerPrivateKeyInfo.privateKeyAlgorithm, issuerPrivateKeyData, hash);

    const issuerAlgorithm = issuerPrivateKey.algorithm.name;
    const isECDSA = issuerAlgorithm == "ECDSA";

    const issuerCertificate = authority != "-" && Pem.read(await readFile(join(authority, "cert.pem"), { encoding: 'utf8' })).decodeSection(Certificate);

    const authorityKeyIdentifier = authority == "-"
        ? keyIdentifier
        : issuerCertificate.tbsCertificate.getExtension(SubjectKeyIdentifier).id;

    const subjectNames = Name.parse(subject);

    const issuerNames = authority == "-"
        ? subjectNames
        : issuerCertificate.tbsCertificate.subject;

    const usageList = usages.split(",");

    const isCA = usageList.includes("ca");
    const isClient = usageList.includes("client");

    if (isCA) await mkdir(join(output, "certificates"));

    const signatureAlgorithmID = signatureIDs.find(signature => signature.hash == hash && signature.algorithm == issuerAlgorithm)?.id;

    const subjectPublicKey = x690.decode(new Uint8Array(publicKeyData), PublicKey);

    const serialNumber = selfSigned ? 0 : 1 + (await readdir(join(authority, "certificates"))).length;

    const tbsCertificate = new TBSCertificate({
        version: 2,
        serialNumber: BigInt(serialNumber),
        signature: signatureAlgorithmID,
        issuer: issuerNames,
        validity: new Validity(
            new Date(),
            parseInterval(validity),
        ),
        subject: subjectNames,
        subjectPublicKeyInfo: subjectPublicKey,
        extensions: [
            Extension.optional(new SubjectKeyIdentifier(keyIdentifier)),
            Extension.optional(new AuthorityKeyIdentifier(authorityKeyIdentifier)),
            Extension.critical(new KeyUsage({
                digitalSignature: isClient || !!dnsNames.length,
                keyCertSign: !!isCA,
            })),
            dnsNames.length ? Extension.optional(new SubjectAltName(dnsNames.map(name => GeneralName.dnsName(name)))) : null,
            Extension.critical(new BasicConstraints(isCA)),
            (dnsNames.length || isClient) && Extension.critical(new ExtendedKeyUsage([
                dnsNames.length && ExtendedKeyUsage.TLS_WEB_SERVER_AUTHENTICATION,
                isClient && ExtendedKeyUsage.TLS_WEB_CLIENT_AUTHENTICATION,
            ].filter(Boolean))),
        ].filter(Boolean),
    });
    const tbs = x690.encode(tbsCertificate);
    const signature = new Uint8Array(await crypto.subtle.sign({ name: issuerAlgorithm, hash }, issuerPrivateKey, tbs));

    let x509Signature;

    if (isECDSA) {
        x509Signature = x690.encode(new X509ECSignature(bytesToBigInt(signature.slice(0, 32)), bytesToBigInt(signature.slice(32))));
    } else {
        x509Signature = signature;
    }

    const certificate = new Certificate(tbsCertificate, signatureAlgorithmID, x509Signature);

    const certificatePem = new Pem();
    certificatePem.encodeSection(certificate);
    const certificateBytes = certificatePem.write()

    await writeFile(join(output, "cert.pem"), certificateBytes);
    if (!selfSigned) await writeFile(join(authority, "certificates", `${subject}-${serialNumber}.pem`), certificateBytes);
}




const transform = {
    Y: "FullYear",
    M: "Month",
    D: "Date",
    h: "Hours",
    m: "Minutes",
    s: "Seconds",
}

export function bytesToBigInt(bytes) {
    return [...bytes]
        .reduce(
            (result, byte) => result * 256n + BigInt(byte),
            0n
        )
}

export function bigintToBytes(bigInt, byteLength) {
    let result = new Uint8Array(byteLength);
    for (let i = byteLength - 1; i >= 0; i--) {
        result[i] = Number(bigInt & 0xffn);
        bigInt = bigInt >> 8n;
    }
    return result;
}


class X509ECSignature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
    }
    static [x690.encoding] = x690.sequence(
        x690.field("r", x690.bigInt()),
        x690.field("s", x690.bigInt()),
    );

    toIEEEP1363() {
        return concatBytes(bigintToBytes(this.r, 32), bigintToBytes(this.s, 32));
    }
}

function add(date, unit, amount = 1) {
    let newDate = new Date(date);
    newDate[`set${transform[unit]}`](newDate[`get${transform[unit]}`]() + amount);
    return newDate;
}


async function get(url, output) {
    let [res] = await once(https.get(url), "response");
    res.on('data', () => 0);
    let certificate = res.socket.getPeerCertificate(true);
    let pem = new Pem();

    while (true) {
        pem.addSection("CERTIFICATE", certificate.raw);
        if (!certificate.issuerCertificate || certificate.issuerCertificate == certificate) break;
        certificate = certificate.issuerCertificate
    }
    await writePem(pem, output);
}


async function verify(issuerCertificateFile, subjectCertificateFile) {
    const issuerCertificate = Pem.read(await readFile(issuerCertificateFile, { encoding: 'utf8' })).decodeSection(Certificate);
    const subjectCertificate = Pem.read(await readFile(subjectCertificateFile, { encoding: 'utf8' })).decodeSection(Certificate);

    const { hash, algorithm } = signatureIDs.find(signature => signature.id.equals(subjectCertificate.signatureAlgorithm)) || {};

    const spki = issuerCertificate.tbsCertificate.subjectPublicKeyInfo;
    const importOID = spki.algorithm.parameters?.id || spki.algorithm.algorithm.id;

    const publicKey = await crypto.subtle.importKey("spki", x690.encode(spki), { ...importParams[importOID], hash }, true, ["verify"]);
    const issuerAlgorithm = publicKey.algorithm.name;
    if (algorithm != issuerAlgorithm) throw "Algorithm mismatch";
    const isECDSA = issuerAlgorithm == "ECDSA";

    //console.log(inspect(publicKey, {depth: 8}));

    const tbs = x690.encode(subjectCertificate.tbsCertificate);

    const signature = isECDSA
        ? x690.decode(subjectCertificate.signature, X509ECSignature).toIEEEP1363()
        : subjectCertificate.signature;


    console.log("Verify", await crypto.subtle.verify({ name: publicKey.algorithm.name, hash }, publicKey, signature, tbs));


    // const issuerKey = Pem.read(await readFile(issuerCertificateFile, { encoding: "utf8" }));
    // const issuerPrivateKey = issuerKey.decodeSection(PKCS8PrivateKeyInfo);
}

function help() {
    console.log(`
x509-io show file.pem
x509-io generate type hash output authority subject usages validity ...dnsNames
        type: secp256r1 or rsa4096
        hash: SHA-512 or SHA-256
        output: a directory will be created here
        authority: a directory containing a privateKey.pem and cert.pem of the certificate authority, or - to self sign
        subject: a slash separated string of DN components, eg: /CN=example.com
        usages: a comma separated list including some of: ca,client,server
        dnsNames: a list of DNS names for the certificate
x509-io verify authority.pem subject.pem
x509-io get https://server [output]
`);
}

const commands = { show, generate, get, verify, help };

const [command, ...args] = process.argv.slice(2);

await (commands[command] || help)(...args);
