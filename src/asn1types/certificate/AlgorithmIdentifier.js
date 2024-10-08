//@ts-check
import * as x690 from 'x690-io';


export default class AlgorithmIdentifier {
    constructor(algorithm, parameters) {
        this.algorithm = algorithm;
        this.parameters = parameters;
    }

    // static forSignature(hashAlgorithm, signatureAlgorithm) {
    //     return signatureTypes.find(signature => signature.hash == hashAlgorithm && signature.algorithm == signatureAlgorithm)?.id;
    // }

    static elliptic(parameters) {
        return new AlgorithmIdentifier(
            new x690.OID("1.2.840.10045.2.1"),
            parameters,
        );
    }

    static ecPrime256v1 = new AlgorithmIdentifier(
        new x690.OID("1.2.840.10045.2.1"),
        new x690.OID("1.2.840.10045.3.1.7")
    );

    static rsa = new AlgorithmIdentifier(
        new x690.OID("1.2.840.113549.1.1.1"),
    );

    static ecdsaWithSha256 = new AlgorithmIdentifier(
        new x690.OID("1.2.840.10045.4.3.2")
    );

    static ecdsaWithSha512 = new AlgorithmIdentifier(
        new x690.OID("1.2.840.10045.4.3.4")
    );

    static rsaWithSha256 = new AlgorithmIdentifier(
        new x690.OID("1.2.840.113549.1.1.11"),
    );

    static rsaWithSha512 = new AlgorithmIdentifier(
        new x690.OID("1.2.840.113549.1.1.13"),
    );

    toSignatureAlgorithm(hash) {
        // let {name} = this.getImportParams(this);
        // return AlgorithmIdentifier.forSignature(hash, name);
        return keyToSignature[this.algorithm.id][hash];
    }

    // https://tools.ietf.org/html/rfc5280#section-4.1.1.2
    static [x690.encoding] = x690.sequence(
        x690.field("algorithm", x690.oid()),
        x690.field("parameters", x690.optional(x690.choice(x690.oid(), x690.nullData()))),
    );

    equals(other) {
        return this.algorithm.equals(other.algorithm) && (
            (other.parameters && this.parameters && this.parameters.equals(other.parameters))
            || (!other.parameters && !this.parameters)
        );
    }

    toString() {
        return `${this.algorithm}-${this.parameters}`;
    }
};


const keyToSignature = {
    "1.2.840.10045.2.1": {
        "SHA-256": AlgorithmIdentifier.ecdsaWithSha256,
        "SHA-512": AlgorithmIdentifier.ecdsaWithSha512,
    },
    "1.2.840.113549.1.1.1": {
        "SHA-256": AlgorithmIdentifier.rsaWithSha256,
        "SHA-512": AlgorithmIdentifier.rsaWithSha512,
    }
};


