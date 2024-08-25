import * as x690 from 'x690-io';
import GeneralName from '../certificate/GeneralName.js';

class AccessDescription {
    static [x690.encoding] = x690.sequence(
        x690.field("accessMethod", x690.oid()),
        x690.field("accessLocation", x690.instance(GeneralName)),
    );
}

export default class AuthorityInformationAccess {

    // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.2.1
    static ID = "1.3.6.1.5.5.7.1.1";
    static [x690.encoding] = x690.field("descriptions", x690.sequenceOf(
        x690.instance(AccessDescription),
    ));
};

