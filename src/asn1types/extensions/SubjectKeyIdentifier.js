import * as x690 from 'x690-io';

export default class SubjectKeyIdentifier {
    constructor(id) {
        this.id = id;
    }
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.2
    static ID = "2.5.29.14";
    static [x690.encoding] = x690.field("id", x690.octetString());
};

