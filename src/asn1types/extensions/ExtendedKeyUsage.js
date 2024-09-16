import * as x690 from 'x690-io';


export default class ExtendedKeyUsage {
    constructor(usages = []) {
        this.usages = usages;
    }

    static TLS_WEB_SERVER_AUTHENTICATION = new x690.OID("1.3.6.1.5.5.7.3.1");
    static TLS_WEB_CLIENT_AUTHENTICATION = new x690.OID("1.3.6.1.5.5.7.3.2");

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.12
    static ID = "2.5.29.37";
    static [x690.encoding] = x690.field("usages", x690.sequenceOf(x690.oid()));
};

