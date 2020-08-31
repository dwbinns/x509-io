const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const GeneralName = require('../GeneralName');

module.exports = class SubjectKeyIdentifier {
    constructor() {
        
    }
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.2
    static ID = "2.5.29.14";
    static encoding = field("id", x690.octetString);
};

