import * as x690 from 'x690-io';
import Extension from '../certificate/Extension.js';
import GeneralName from '../certificate/GeneralName.js';
import RDNAttribute from '../certificate/RDNAttribute.js';
import SubjectPublicKeyInfo from '../certificate/SubjectPublicKeyInfo.js';


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
            [[RDNAttribute.commonName(commonName)]],
            SubjectPublicKeyInfo.ecPrime256v1(publicKey),
            dnsNames.length
                ? [RDNAttribute.extensionRequests(
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
    static [x690.encoding] = x690.sequence(
        x690.field('version', x690.integer()),
        x690.field('subject', x690.sequenceOf(x690.setOf(x690.instance(RDNAttribute)))),
        x690.field('subjectPKInfo', x690.instance(SubjectPublicKeyInfo)),
        x690.field('attributes', x690.implicit(0, x690.sequenceOf(x690.instance(RDNAttribute)), []))
    );

}
export default CertificationRequestInfo;