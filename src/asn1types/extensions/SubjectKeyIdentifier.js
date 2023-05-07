import { field, instance } from 'structured-io';
import * as x690 from 'x690-io';import GeneralName from '../GeneralName.js';

export default class SubjectKeyIdentifier {
    constructor() {
        
    }
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.2
    static ID = "2.5.29.14";
    static encoding = field("id", x690.octetString);
};

