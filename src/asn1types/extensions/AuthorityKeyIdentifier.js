import * as x690 from 'x690-io';
import GeneralName from '../certificate/GeneralName.js';

export default class AuthorityKeyIdentifier {
    constructor(keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
    static ID = "2.5.29.35";
    static [x690.encoding] = x690.sequence(
        x690.field("keyIdentifier", x690.optional(x690.implicit(0, x690.octetString()))),
        x690.field("authorityCertIssuer", x690.optional(x690.implicit(1, x690.sequence(x690.instance(GeneralName))))),
        x690.field("authorityCertSerialNumber", x690.optional(x690.implicit(2, x690.bigInt()))),

    );

    //static [x690.encoding] = field("data", x690.auto);
};

