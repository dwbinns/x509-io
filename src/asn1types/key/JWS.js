export default class JWS {
    constructor(payload, protectedHeader, signature) {
        this.payload = payload;
        this.protected = protectedHeader;
        this.signature = signature;
    }

    compact() {
        // https://tools.ietf.org/html/rfc7515#section-7.1
        return `${this.protected}.${this.payload}.${this.signature}`;
    }

    flattened() {
        // https://tools.ietf.org/html/rfc7515#section-7.2.2
        return {
            payload: this.payload,
            protected: this.protected,
            signature: this.signature,
        };
    }
}
