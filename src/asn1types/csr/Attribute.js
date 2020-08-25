const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const Extension = require('../Extension');

class Attribute {
    static encoding = x690.sequence(
        field('type', x690.oid),
        field('values', x690.setOf(x690.sequenceOf(instance(Extension))) )
    );
}
module.exports = Attribute;
