const { optional, field, instance } = require('structured-io');
const x690 = require('x690-io');
const GeneralName = require('../GeneralName');

module.exports = class BasicConstraints {
    constructor(cA, pathLenConstraint) {
        this.cA = cA;
        this.pathLenConstraint = pathLenConstraint;
    }

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.9
    static ID = "2.5.29.19";
    static encoding = x690.sequence(
        field("cA", optional(false, x690.boolean)),
        field("pathLenConstraint", optional(null, x690.integer))
    );
};

