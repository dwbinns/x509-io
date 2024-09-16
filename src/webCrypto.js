//@ts-check
import * as x690 from "x690-io";
import AlgorithmIdentifier from "./asn1types/certificate/AlgorithmIdentifier.js";
import TBSCertificate from "./asn1types/certificate/TBSCertificate.js";
import PKCS8PrivateKeyInfo from "./asn1types/key/PKCS8PrivateKeyInfo.js";
import X509ECSignature from "./asn1types/key/X509ECSignature.js";
import Certificate from "./asn1types/certificate/Certificate.js";



class WebCrypto {
    async keyIdentifier(bytes) {
        return await crypto.subtle.digest("SHA-256", bytes);
    }

    async sign(pkcs8Key, hash, content) {
        let params = getImportParams(pkcs8Key.privateKeyAlgorithm, hash);
        let privateKey = await crypto.subtle.importKey("pkcs8", pkcs8Key.toBytes(), params, true, ["sign"])
        let name = privateKey.algorithm.name;
        let isECDSA = name == "ECDSA";
        const signature = new Uint8Array(await crypto.subtle.sign({ name, hash }, privateKey, content));

        return isECDSA
            ? x690.encode(X509ECSignature.fromWebCrypto(signature))
            : signature;
    }

    async generate(type) {
        const hash = "SHA-256"; // Not used, but required
        const keyPair = await crypto.subtle.generateKey({ ...generateParams[type], hash }, true, ["sign"]);
        const pkcs8Bytes = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        return PKCS8PrivateKeyInfo.fromBytes(pkcs8Bytes);
    }


    async verify(spki, signatureAlgorithm, signature, content) {
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
}

export const webCrypto = new WebCrypto();


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




export class Signing {
    constructor(key, certificate) {
        this.key = key;
        this.certificate = certificate;
    }

    get certificatePem() {
        return x690.Pem.encode(this.certificate).write();
    }

    get privateKeyPem() {
        return x690.Pem.encode(this.key).write();
    }

    get publicKeyPem() {
        return this.key.toSPKI().toPem().write();
    }

    async sign(subject, params) {
        return await Signing.create(this, subject, params);
    }

    async server(hostname) {
        return await this.sign(`CN=${hostname}`, { server: true, dnsNames: [hostname] });
    }

    static async CA() {
        return this.selfSigned("CN=CA", { ca: true });
    }

    static async selfSigned(subject, params) {
        return await this.create(null, subject, params);
    }

    static async create(authority, subject, { hash = "SHA-256", type = "secp256r1", serialNumber = 1, validity = "1D", ca = false, server = false, client = false, dnsNames = [] } = {}) {
        const key = await webCrypto.generate(type);
        const spki = key.toSPKI();

        const keyIdentifier = await webCrypto.keyIdentifier(spki.toBytes());

        const authorityKey = authority?.key || key;

        const tbsCertificate = TBSCertificate.create(authority?.certificate, subject, spki, keyIdentifier, serialNumber, validity, client, server, ca, dnsNames);

        const signatureAlgorithm = authorityKey.privateKeyAlgorithm.toSignatureAlgorithm(hash);
        tbsCertificate.setSigningAlgorithmId(signatureAlgorithm);
        const certificate = new Certificate(tbsCertificate, signatureAlgorithm, await webCrypto.sign(authorityKey, hash, tbsCertificate.getBytes()));

        return new Signing(key, certificate);
    }
}



export async function testCertificate(subject, options = {}) {
    let ca = await Signing.CA();
    let signing = await ca.sign(`CN=${subject}`, { server: true, client: false, dnsNames: [subject], ...options });
    return {
        ca: ca.certificatePem,
        cert: signing.certificatePem,
        key: signing.privateKeyPem,
    };
}

