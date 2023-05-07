import { optional, field, instance } from 'structured-io';
import * as x690 from 'x690-io';import GeneralName from '../GeneralName.js';

export default class BasicConstraints {
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

