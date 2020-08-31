const { field } = require('structured-io');
const x690 = require('x690-io');
const OID = require('x690-io/src/OID');


class Name {

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.4
    static encoding = x690.sequence(
        field('type', x690.oid),
        field('value', x690.anyString)
    );

    constructor(type, value) {
        this.type = type;
        this.value = value;
    }

    static commonName(value) {
        return new Name(new OID("2.5.4.3"), value);
    }

    // constructor(name, value) {
    //     this.name = name;
    //     this.value = value;
    // }
}

module.exports = Name;