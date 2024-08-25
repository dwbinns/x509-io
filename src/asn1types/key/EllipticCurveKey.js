import { Pem } from "x690-io";
import ECPrivateKey from "./ECPrivateKey.js";
import JWS from "./JWS.js";
import PKCS8PrivateKeyInfo from "./PKCS8PrivateKeyInfo.js";
import PublicKey from "./PublicKey.js";


class EllipticCurveKey {
    constructor(pkcs8Pem) {
        this.pkcs8Pem = pkcs8Pem;
    }

    static fromJWK(jwk) {
        let privateKey = ECPrivateKey.fromJWK(jwk).makePKCS8();
        return new EllipticCurveKey(new Pem(Pem.Section.encodeContent([["PRIVATE KEY", PKCS8PrivateKeyInfo]], privateKey)).write());
    }

    static async load(filePath) {
        return new EllipticCurveKey(await readFile(filePath, { encoding: "utf8" }));
    }

    static async generate() {
        const ec = await generateKeyPair('ec', {
            namedCurve: 'prime256v1'
        });

        return new EllipticCurveKey(ec.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    }

    async save(filePath) {
        await writeFile(filePath, this.pkcs8Pem);
        return this;
    }

    getPKCS8PrivateKey() {
        let sections = Pem.read(this.pkcs8Pem).sections;
        let section = sections.find(({ type }) => type == "PRIVATE KEY");
        if (!section) throw new Error("Key conversion failed");
        return read(section.content, PKCS8PrivateKeyInfo);
    }

    toPrivateKeyJWK() {
        // https://tools.ietf.org/html/rfc7517
        // https://tools.ietf.org/html/rfc7518

        let ecPrivateKey = ECPrivateKey.fromPKCS8(this.getPKCS8PrivateKey());

        let d = base64url(ecPrivateKey.privateKey);
        let { x, y } = unpackPublicKey(ecPrivateKey.publicKey, 32);
        let kty = "EC";
        let crv = "P-256";
        return { kty, crv, d, x, y };
    }

    toPublicKeyJWK() {
        let ecPrivateKey = ECPrivateKey.fromPKCS8(this.getPKCS8PrivateKey());

        let { x, y } = unpackPublicKey(ecPrivateKey.publicKey, 32);
        let kty = "EC";
        let crv = "P-256";
        return { kty, crv, x, y };
    }

    toPrivateKeyPem() {
        return this.pkcs8Pem;
    }

    toPublicKeyPem() {
        let pkcs8Key = this.getPKCS8PrivateKey();
        let ecPrivateKey = ECPrivateKey.fromPKCS8(pkcs8Key);
        let publicKey = new PublicKey(pkcs8Key.privateKeyAlgorithm, ecPrivateKey.publicKey);
        return new Pem(Pem.Section.encodeContent("PUBLIC KEY", publicKey)).write();

    }

    toPublicKeyBitString() {

        let pkcs8Key = this.getPKCS8PrivateKey();
        let ecPrivateKey = ECPrivateKey.fromPKCS8(pkcs8Key);
        return ecPrivateKey.publicKey;
    }

    sign(headers, content) {
        let encodedHeader = base64url(Buffer.from(JSON.stringify({ "alg": "ES256", ...headers })));

        let encodedPayload = base64url(Buffer.from(content));

        const sign = createSign("SHA256");

        sign.end(`${encodedHeader}.${encodedPayload}`);

        let signature = base64url(sign.sign({ dsaEncoding: 'ieee-p1363', key: this.pkcs8Pem }));

        return new JWS(encodedPayload, encodedHeader, signature);
    }

    getThumbprint() {
        // https://tools.ietf.org/html/rfc7638#section-3.2
        let { crv, kty, x, y } = this.toPublicKeyJWK();
        return base64url(createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest());
    }
}

async function main() {
    //let signingKey = await SigningKey.generate();
    let jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
    };
    let signingKey = EllipticCurveKey.fromJWK(jwk);

    console.log(signingKey.toPrivateKeyPem());
    console.log(signingKey.toPrivateKeyJWK());
    console.log(signingKey.toPublicKeyPem());
    console.log(signingKey.sign({}, JSON.stringify({ "iss": "joe", "exp": 1300819380, "http://example.com/is_root": true })).compact());


    //CertificationRequestInfo.for({"2.5.4.3": "example.com"}, );

}

//if (require.main == module) main().catch(console.error);

export default EllipticCurveKey;