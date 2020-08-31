const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const GeneralName = require('../GeneralName');

module.exports = class SubjectAltName {
    constructor(...names) {
        this.names = names;
    }

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    static ID = "2.5.29.17";
    static encoding = field("names", x690.sequenceOf(instance(GeneralName)));
};

