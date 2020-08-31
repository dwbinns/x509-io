const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const Extension = require('../Extension');

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
module.exports = Attribute;
