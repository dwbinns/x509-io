import { field, instance } from 'structured-io';
import * as x690 from 'x690-io';
import Attribute from './Attribute.js';
import Name from '../Name.js';
import SubjectPublicKeyInfo from '../SubjectPublicKeyInfo.js';
import Extension from '../Extension.js';
import GeneralName from '../GeneralName.js';

class CertificationRequestInfo {
    constructor(version, subject, subjectPKInfo, attributes) {
        this.version = version;
        this.subject = subject;
        this.subjectPKInfo = subjectPKInfo;
        this.attributes = attributes;
    }

    static forNames(publicKey, commonName, ...dnsNames) {
        return new CertificationRequestInfo(
            0,
            [[Name.commonName(commonName)]],
            SubjectPublicKeyInfo.ecPrime256v1(publicKey),
            dnsNames.length
                ? [Attribute.extensionRequests(
                    Extension.subjectAltName(
                        ...dnsNames.map(name => GeneralName.dnsName(name))
                    )
                )]
                : []
        )
    }

    // static for(nameObject) {
    //     Object.keys(nameObject).map(([key, value]) => key
    //     return CertificationRequestInfo(0, );
    // }

    // https://tools.ietf.org/html/rfc2986#section-4
    static encoding = x690.sequence(
        field('version', x690.integer),
        field('subject', x690.sequenceOf(x690.setOf(instance(Name)))),
        field('subjectPKInfo', instance(SubjectPublicKeyInfo)),
        field('attributes', x690.implicit(0, x690.sequenceOf(instance(Attribute)), []))
    );

}
export default CertificationRequestInfo;