const { field, instance } = require('structured-io');
const { oid } = require('x690-io');
const x690 = require('x690-io');
const Attribute = require('./Attribute');
const Name = require('../Name');
const SubjectPublicKeyInfo = require('../SubjectPublicKeyInfo');

class CertificationRequestInfo {
    constructor(version, subject, subjectPKInfo, attributes) {
        this.version = version;
        this.subject = subject;
    }

    // static for(nameObject) {
    //     Object.keys(nameObject).map(([key, value]) => key
    //     return CertificationRequestInfo(0, );
    // }

    static encoding = x690.sequence(
        field('version', x690.integer),
        field('subject', x690.sequence(x690.setOf(instance(Name)))),
        field('subjectPKInfo', instance(SubjectPublicKeyInfo)),
        field('attributes', x690.implicit(0, x690.sequenceOf(instance(Attribute)), []))
    );

}
module.exports = CertificationRequestInfo;