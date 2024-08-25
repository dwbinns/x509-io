import * as x690 from 'x690-io';

export default class BasicConstraints {
    constructor(cA, pathLenConstraint) {
        this.cA = cA;
        this.pathLenConstraint = pathLenConstraint;
    }

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.9
    static ID = "2.5.29.19";
    static [x690.encoding] = x690.sequence(
        x690.field("cA", x690.optional(x690.boolean(), false)),
        x690.field("pathLenConstraint", x690.optional(x690.integer()))
    );
};

