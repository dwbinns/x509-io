import * as x690 from 'x690-io';

class NoticeReference {
    static [x690.encoding] = x690.sequence(
        x690.field("organization", x690.anyString()),
        x690.field("noticeNumbers", x690.sequenceOf(x690.bigInt())),
    );
}

class UserNotice {
    static [x690.encoding] = x690.sequence(
        x690.field("noticeRef", x690.instance(NoticeReference)),
        x690.field("explicitText", x690.anyString()),
    );
}

class QualifierInfo {
    static [x690.encoding] = x690.sequence(
        x690.field("policyQualifierId", x690.oid()),
        x690.field("qualifier", x690.choice(
            x690.ia5String(),
            x690.instance(UserNotice),
        )),
    );
}

class Policy {
    static [x690.encoding] = x690.sequence(
        x690.field("policyIdentifier", x690.oid()),
        x690.field("policyQualifiers", x690.optional(x690.sequenceOf(x690.instance(QualifierInfo)))),
    );
}

export default class CertificatePolicies {
    constructor() {

    }

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.4
    static ID = "2.5.29.32";
    static [x690.encoding] = x690.field("certificatePolicies", x690.sequenceOf(x690.instance(Policy)));
};

