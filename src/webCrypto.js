//@ts-check
import * as x690 from "x690-io";
import AlgorithmIdentifier from "./asn1types/certificate/AlgorithmIdentifier.js";
import TBSCertificate from "./asn1types/certificate/TBSCertificate.js";
import PKCS8PrivateKeyInfo from "./asn1types/key/PKCS8PrivateKeyInfo.js";
import X509ECSignature from "./asn1types/key/X509ECSignature.js";
import Certificate from "./asn1types/certificate/Certificate.js";
import { CertificationRequest, CertificationRequestInfo } from "../library.js";



async function keyIdentifier(bytes) {
    return await crypto.subtle.digest("SHA-256", bytes);
}

export async function importKey(pkcs8Key, hash) {
    let params = getImportParams(pkcs8Key.privateKeyAlgorithm, hash);
    return await crypto.subtle.importKey("pkcs8", pkcs8Key.toBytes(), params, true, ["sign"])
}

export async function sign(pkcs8Key, hash, content) {
    let privateKey = await importKey(pkcs8Key, hash);
    let name = privateKey.algorithm.name;
    let isECDSA = name == "ECDSA";
    const signature = new Uint8Array(await crypto.subtle.sign({ name, hash }, privateKey, content));

    return isECDSA
        ? x690.encode(X509ECSignature.fromWebCrypto(signature))
        : signature;
}

export async function generate(type) {
    const hash = "SHA-256"; // Not used, but required
    const keyPair = await crypto.subtle.generateKey({ ...generateParams[type], hash }, true, ["sign"]);
    const pkcs8Bytes = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    return PKCS8PrivateKeyInfo.fromBytes(pkcs8Bytes);
}


export async function verify(spki, signatureAlgorithm, signature, content) {
    const { hash, algorithm } = getSignatureParams(signatureAlgorithm);

    const importParams = getImportParams(spki.algorithm);
    const publicKey = await crypto.subtle.importKey("spki", spki.toBytes(), { ...importParams, hash }, true, ["verify"]);

    const issuerAlgorithm = publicKey.algorithm.name;
    if (algorithm != issuerAlgorithm) throw "Algorithm mismatch";
    const isECDSA = issuerAlgorithm == "ECDSA";

    const webCryptoSignature = isECDSA
        ? x690.decode(signature, X509ECSignature).toIEEEP1363()
        : signature;

    const params = { name: publicKey.algorithm.name, hash };

    return await crypto.subtle.verify(params, publicKey, webCryptoSignature, content);
}


export async function makeCSR(subjectPrivateKey, hash, subject, { ca = false, server = false, client = false, dnsNames = [] } = {}) {

    const spki = subjectPrivateKey.toSPKI();

    const keyId = await keyIdentifier(spki.toBytes());

    const signatureAlgorithm = subjectPrivateKey.privateKeyAlgorithm.toSignatureAlgorithm(hash);

    const csrInfo = CertificationRequestInfo.create(subject, spki, keyId, client, server, ca, dnsNames);

    const signature = await sign(subjectPrivateKey, hash, csrInfo.getBytes());

    return new CertificationRequest(csrInfo, signatureAlgorithm, signature);
}

export async function makeCertificate(authorityPrivateKey, hash, csr, serialNumber = 1, validity = "1D", authorityCertificate) {
    const tbsCertificate = TBSCertificate.createFromCSR(csr, serialNumber, validity, authorityCertificate);

    const signatureAlgorithm = authorityPrivateKey.privateKeyAlgorithm.toSignatureAlgorithm(hash);
    tbsCertificate.setSigningAlgorithmId(signatureAlgorithm);
    const signature = await sign(authorityPrivateKey, hash, tbsCertificate.getBytes());
    return new Certificate(tbsCertificate, signatureAlgorithm, signature);
}


const ECDSA = "ECDSA";
const RSA = 'RSASSA-PKCS1-v1_5';
const SHA256 = "SHA-256";
const SHA512 = "SHA-512";

const signatureTypes = [
    { id: AlgorithmIdentifier.ecdsaWithSha256, hash: SHA256, algorithm: ECDSA },
    { id: AlgorithmIdentifier.ecdsaWithSha512, hash: SHA512, algorithm: ECDSA },
    { id: AlgorithmIdentifier.rsaWithSha256, hash: SHA256, algorithm: RSA },
    { id: AlgorithmIdentifier.rsaWithSha512, hash: SHA512, algorithm: RSA },
];

const keyTypes = [
    { id: AlgorithmIdentifier.ecPrime256v1, import: { name: ECDSA, namedCurve: "P-256" } },
    { id: AlgorithmIdentifier.rsa, import: { name: RSA } },
];


const find = (list, id) => list.find(item => item.id.equals(id));

function getImportParams(id, hash) {
    const importParams = find(keyTypes, id)?.import;
    if (!importParams) throw new Error(`Unknown key type: ${this}`);
    return { ...importParams, hash };
}

function getSignatureParams(id) {
    const { hash, algorithm } = find(signatureTypes, id);
    if (!hash) throw new Error("Unknown signature type");
    return { hash, algorithm };
}

const generateParams = {
    "RSA-4096": {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    "RSA-1024": {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 1024,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    },
    "secp256r1": {
        name: "ECDSA",
        namedCurve: "P-256"
    },
};




export async function testCertificate(subject, { server = true, client = true, dnsNames = server ? [subject] : [] } = {}) {
    let caKey = await generate("secp256r1");
    let caCert = await makeCertificate(caKey, "SHA-256", await makeCSR(caKey, "SHA-256", "CN=CA", { ca: true }), 0, "1D");

    let key = await generate("secp256r1");
    let cert = await makeCertificate(caKey, "SHA-256", await makeCSR(key, "SHA-256", `CN=${subject}`, { server, client, dnsNames }), 0, "1D", caCert);

    // let ca = await Signing.CA();
    // let signing = await ca.sign(`CN=${subject}`, { server: true, client: false, dnsNames: [subject], ...options });
    return {
        ca: caCert.toPem().write(),
        cert: cert.toPem().write(),
        key: key.toPem().write(),
    };
}

