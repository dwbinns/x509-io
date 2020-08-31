const {field, optional } = require('structured-io');
const x690 = require('x690-io');


class AlgorithmIdentifier {
    constructor(algorithm, parameters = null) {
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

    // https://tools.ietf.org/html/rfc5280#section-4.1.1.2
    static encoding = x690.sequence(
        field("algorithm", x690.oid),
        field("parameters", optional(null, x690.choice(x690.oid, x690.nullData))),
    );
}
module.exports = AlgorithmIdentifier;
