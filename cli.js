#!/usr/bin/env node
//@ts-check
import * as hex from "@dwbinns/base/hex";
import { yellow } from '@dwbinns/terminal/colour';
import tree from "@dwbinns/terminal/tree";
import { once } from "node:events";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import https from 'node:https';
import { join } from "node:path";
import { Certificate, CertificationRequest } from 'x509-io';
import * as x690 from "x690-io";
import SubjectPublicKeyInfo from './src/asn1types/certificate/SubjectPublicKeyInfo.js';
import ECPrivateKey from './src/asn1types/key/ECPrivateKey.js';
import PKCS8PrivateKeyInfo from './src/asn1types/key/PKCS8PrivateKeyInfo.js';
import RSAPublicKey from "./src/asn1types/key/RSAPublicKey.js";
import * as webCrypto from "./src/webCrypto.js";

Error.stackTraceLimit = Infinity;

function children(object, prototype = object) {
    if (object instanceof Array) return [...object.entries()];
    if (!prototype || prototype == Object.prototype) return [];
    return [
        ...Object.getOwnPropertyNames(prototype)
            .map(name => /**@type {[string, PropertyDescriptor]}*/([name, Object.getOwnPropertyDescriptor(prototype, name)]))
            .filter(([, descriptor]) => descriptor.get || (descriptor.value != undefined && typeof descriptor.value != "function"))
            .map(([name]) => [name, object[name]]),
        ...children(object, Object.getPrototypeOf(prototype))
    ];
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

const types = [Certificate, CertificationRequest, SubjectPublicKeyInfo, ECPrivateKey, PKCS8PrivateKeyInfo, RSAPublicKey];
const typeLookup = new Map(types.map(type => [type[x690.name], type]));

async function show(input) {
    for (let section of x690.Pem.read(await readFile(input, { encoding: 'utf8' })).sections) {
        console.log(section.type);
        console.log(objectTree(section.type, section.decodeContent(typeLookup.get(section.type))));
    }
}


async function writePem(pem, output) {
    if (output) await writeFile(output, pem.write());
    else console.log(pem.write());
}


async function readPemFile(path, type) {
    return x690.Pem.read(await readFile(path)).decodeSection(type);
}

async function generate(type, hash, output, authority, subject, usageList, validity, ...dnsNames) {
    await mkdir(output);

    const usages = new Set(usageList.split(","));
    const ca = usages.has("ca");
    const server = usages.has("server");
    const client = usages.has("client");

    if (ca) await mkdir(join(output, "certificates"));

    let subjectPrivateKey = await webCrypto.generate(type);

    await writeFile(join(output, "privateKey.pem"), subjectPrivateKey.toPem().write());
    await writeFile(join(output, "publicKey.pem"), subjectPrivateKey.toSPKI().toPem().write());


    let csr = await webCrypto.makeCSR(subjectPrivateKey, hash, subject, { ca, server, client, dnsNames });

    await writeFile(join(output, "csr.pem"), csr.toPem().write());

    if (authority == "-") return;

    const selfSigned = authority == "@";
    const authorityPrivateKey = selfSigned ? subjectPrivateKey : await readPemFile(join(authority, "privateKey.pem"), PKCS8PrivateKeyInfo);
    const authorityCertificate = selfSigned ? null : await readPemFile(join(authority, "cert.pem"), Certificate);

    const serialNumber = selfSigned ? 0 : 1 + (await readdir(join(authority, "certificates"))).length;

    let certificate = await webCrypto.makeCertificate(authorityPrivateKey, hash, csr, serialNumber, validity, authorityCertificate);

    let certificateText = certificate.toPem().write();

    await writeFile(join(output, "cert.pem"), certificateText);
    if (!selfSigned) await writeFile(join(authority, "certificates", `${subject}-${serialNumber}.pem`), certificateText);
}




async function get(url, output) {
    let [res] = await once(https.get(url), "response");
    res.on('data', () => 0);
    let certificate = res.socket.getPeerCertificate(true);
    let pem = new x690.Pem();

    while (true) {
        pem.addSection("CERTIFICATE", certificate.raw);
        if (!certificate.issuerCertificate || certificate.issuerCertificate == certificate) break;
        certificate = certificate.issuerCertificate
    }
    await writePem(pem, output);
}


async function verify(issuerCertificateFile, subjectCertificateFile) {
    const issuerCertificate = await readPemFile(issuerCertificateFile, Certificate);
    const subjectCertificate = await readPemFile(subjectCertificateFile, Certificate);

    const tbs = subjectCertificate.tbsCertificate[x690.bytes];

    let verification = await webCrypto.verify(issuerCertificate.tbsCertificate.subjectPublicKeyInfo, subjectCertificate.signatureAlgorithm, subjectCertificate.signature, tbs);
    //let verification = await issuerCertificate.tbsCertificate.subjectPublicKeyInfo.verifyX509(subjectCertificate.signatureAlgorithm, subjectCertificate.signature, tbs);

    console.log("Verify", verification);

    return verification ? 0 : 1;
}

function help() {
    console.log(`
x509-io show file.pem 
    Describe a PEM file's content
x509-io generate <type> <hash> <output> <authority> <subject> <usages> <validity> <dnsName> [<dnsName>...]
    Generate a private key and certificate, either self signed or signed by an authority private key and certificate
        <type>: private key type: secp256r1, RSA-4096, RSA-1024
        <hash>: hash used in signature: SHA-512 or SHA-256
        <output>: a directory will be created here containing cert.pem and privateKey.pem
        <authority>: a directory containing a privateKey.pem and cert.pem of the certificate authority, or - to self sign
        <subject>: a slash separated string of DN components, eg: /CN=example.com
        <usages>: a comma separated list including some of: ca,client,server
        <dnsName>: DNS names for the certificate        <subject>: a slash separated string of DN components, eg: /CN=example.com
        <usages>: a comma separated list including some of: ca,client,server
        <dnsName>: DNS names for the certificate
x509-io verify authority.pem subject.pem
x509-io get https://server [output]
`);
}

const commands = { show, generate, get, verify, help };

const [command, ...args] = process.argv.slice(2);

process.exitCode = (await (commands[command] || help)(...args).catch(e => { console.error(e); return 2; })) || 0;
