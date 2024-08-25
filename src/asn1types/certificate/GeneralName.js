import * as x690 from 'x690-io';

class GeneralName {
    constructor(type, value) {
        if (type) {
            this[type] = value;
        }
    }

    static rfc822Name(name) {
        return new GeneralName("rfc822Name", name);
    }

    static dnsName(name) {
        return new GeneralName("dnsName", name);
    }

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    // static [x690.encoding] = x690.sequence(
    //     x690.field("rfc822Name", x690.optional(x690.implicit(1, x690.ia5String()))),
    //     x690.field("dnsName", x690.optional(x690.implicit(2, x690.ia5String()))),
    //     x690.field("uniformResourceIdentifier", x690.optional(x690.implicit(6, x690.ia5String()))),
    //     x690.field("ipAddress", x690.optional(x690.implicit(7, x690.octetString()))),
    // );

    static [x690.encoding] = x690.choice(
        x690.field("rfc822Name", x690.implicit(1, x690.ia5String())),
        x690.field("dnsName", x690.implicit(2, x690.ia5String())),
        x690.field("uniformResourceIdentifier", x690.implicit(6, x690.ia5String())),
        x690.field("ipAddress", x690.implicit(7, x690.octetString())),
    );
}

export default GeneralName;