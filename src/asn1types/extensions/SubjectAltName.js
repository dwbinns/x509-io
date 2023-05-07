import { field, instance } from 'structured-io';
import * as x690 from 'x690-io';import GeneralName from '../GeneralName.js';

export default class SubjectAltName {
    constructor(...names) {
        this.names = names;
    }

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    static ID = "2.5.29.17";
    static encoding = field("names", x690.sequenceOf(instance(GeneralName)));
};

