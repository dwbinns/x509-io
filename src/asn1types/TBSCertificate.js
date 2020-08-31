const { sequence, call, optional, field, instance } = require('structured-io');
const x690 = require('x690-io');
const Name = require("./Name");
const Extension = require("./Extension");
const AlgorithmIdentifier = require("./AlgorithmIdentifier");
const Validity = require("./Validity");
const SubjectPublicKeyInfo = require("./SubjectPublicKeyInfo");

class TBSCertificate {
    // https://tools.ietf.org/html/rfc5280#section-4.1.1.1
    static encoding = x690.sequence(

        field('version', optional(0, x690.explicit(0, x690.integer))),
        field('serialNumber', x690.use(x690.integer, x690.octetString)),
        field('signature', instance(AlgorithmIdentifier)),
        field('issuer', x690.sequenceOf(x690.setOf(instance(Name)))),
        field('validity', instance(Validity)),
        field('subject', x690.sequenceOf(x690.setOf(instance(Name)))),
        field('subjectPublicKeyInfo', instance(SubjectPublicKeyInfo)),
        field('issuerUniqueID', optional(null, x690.explicit(1, x690.octetString), null)),
        field('subjectUniqueID', optional(null, x690.explicit(2, x690.octetString), null)),
        field('extensions', x690.explicit(3, x690.sequenceOf(instance(Extension)), []))
    );
}
module.exports = TBSCertificate;
