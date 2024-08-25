import * as x690 from 'x690-io';


class AlgorithmIdentifier {
    constructor(algorithm, parameters) {
        this.algorithm = algorithm;
        this.parameters = parameters;
    }

    static ecPrime256v1 = new AlgorithmIdentifier(
        new x690.OID("1.2.840.10045.2.1"),
        new x690.OID("1.2.840.10045.3.1.7")
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
}
export default AlgorithmIdentifier;
