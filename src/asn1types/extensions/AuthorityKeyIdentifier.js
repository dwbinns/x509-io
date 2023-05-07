import { optional, field, instance } from 'structured-io';
import * as x690 from 'x690-io';
import GeneralName from '../GeneralName.js';

export default class AuthorityKeyIdentifier {
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.9
    static ID = "2.5.29.35";
    static encoding = x690.sequence(
        field("keyIdentifier", optional(null, x690.implicit(0, x690.octetString))),
        field("authorityCertIssuer", optional(null, x690.implicit(1, x690.sequence(instance(GeneralName))))),
        field("authorityCertSerialNumber", optional(null, x690.implicit(2, x690.bigint))),

    );

    //static encoding = field("data", x690.auto);
};

