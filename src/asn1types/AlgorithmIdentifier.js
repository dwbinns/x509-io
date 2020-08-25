const { field } = require('structured-io');
const x690 = require('x690-io');

class AlgorithmIdentifier {
    static encoding = x690.sequence(
        field("algorithm", x690.oid),
        field("parameters", x690.nullData),
    );
}
module.exports = AlgorithmIdentifier;
