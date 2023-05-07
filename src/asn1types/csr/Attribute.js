import { field, instance } from 'structured-io';
import * as x690 from 'x690-io';import Extension from '../Extension.js';

class Attribute {
    constructor(type, values) {
        this.type = type;
        this.values = values;
    }

    static extensionRequests(...extensions) {
        return new Attribute(
            new x690.OID("1.2.840.113549.1.9.14"),
            [extensions],
        );
    }

    static encoding = x690.sequence(
        field('type', x690.oid),
        field('values', x690.setOf(x690.sequenceOf(instance(Extension))) )
    );
}
export default Attribute;
