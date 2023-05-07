import * as x690 from 'x690-io';
import { field, sequence, optional } from 'structured-io';

class GeneralName {
    constructor(type, value) {
        this[type] = value;
    }

    static rfc822Name(name) {
        return new GeneralName("rfc822Name", name);
    }

    static dnsName(name) {
        return new GeneralName("dnsName", name);
    }

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    static encoding = sequence(
        field("rfc822Name", optional(null, x690.implicit(1, x690.ia5String))),
        field("dnsName", optional(null, x690.implicit(2, x690.ia5String))),
        field("uniformResourceIdentifier", optional(null, x690.implicit(6, x690.ia5String))),
        field("ipAddress", optional(null, x690.implicit(7, x690.octetString))),
    );
}

export default GeneralName;