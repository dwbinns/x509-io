import * as x690 from 'x690-io';
import Extension from '../certificate/Extension.js';

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

    static [x690.encoding] = x690.sequence(
        x690.field('type', x690.oid()),
        x690.field('values', x690.setOf(x690.sequenceOf(x690.instance(Extension))) )
    );
}
export default Attribute;
