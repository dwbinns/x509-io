const x690 = require('x690-io');
const {field} = require("structured-io");

class GeneralName {
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    static encoding = x690.choice(
        field("rfc822Name", x690.implicit(1, x690.ia5String)),
        field("rfc822Name", x690.implicit(1, x690.ia5String)),
        field("dnsName", x690.implicit(2, x690.ia5String)),
        field("rfc822Name", x690.implicit(7, x690.octetString)),
    );
}

module.exports = GeneralName;