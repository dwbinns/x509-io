const { field, instance } = require('structured-io');
const x690 = require('x690-io');
const GeneralName = require('../GeneralName');

class AccessDescription {
    static encoding = x690.sequence(
        field("accessMethod", x690.oid),
        field("accessLocation", GeneralName)
    );
}

module.exports = class AuthorityInformationAccess {

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    static ID = "1.3.6.1.5.5.7.1.1";
    static encoding = field("descriptions", x690.sequenceOf(
        instance(AccessDescription)
    ));
};

