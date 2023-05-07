import { field, instance } from 'structured-io';
import * as x690 from 'x690-io';import GeneralName from '../GeneralName.js';

class AccessDescription {
    static encoding = x690.sequence(
        field("accessMethod", x690.oid),
        field("accessLocation", GeneralName)
    );
}

export default class AuthorityInformationAccess {

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    static ID = "1.3.6.1.5.5.7.1.1";
    static encoding = field("descriptions", x690.sequenceOf(
        instance(AccessDescription)
    ));
};

