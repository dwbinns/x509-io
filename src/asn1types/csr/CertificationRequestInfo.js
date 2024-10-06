import * as x690 from 'x690-io';
import Extension from '../certificate/Extension.js';
import GeneralName from '../certificate/GeneralName.js';
import RDNAttribute from '../certificate/RDNAttribute.js';
import SubjectPublicKeyInfo from '../certificate/SubjectPublicKeyInfo.js';
import Attribute from './Attribute.js';
import SubjectAltName from '../extensions/SubjectAltName.js';
import Name from '../certificate/Name.js';
import KeyUsage from '../extensions/KeyUsage.js';
import ExtendedKeyUsage from '../extensions/ExtendedKeyUsage.js';
import SubjectKeyIdentifier from '../extensions/SubjectKeyIdentifier.js';
import BasicConstraints from '../extensions/BasicConstraints.js';


class CertificationRequestInfo {
    /**
     * @param {number} version
     * @param {Name | RDNAttribute[][]} subject
     * @param {SubjectPublicKeyInfo} subjectPKInfo
     * @param {Attribute[]} attributes
     */
    constructor(version, subject, subjectPKInfo, attributes) {
        this.version = version;
        this.subject = subject;
        this.subjectPKInfo = subjectPKInfo;
        this.attributes = attributes;
    }

    static create(subject, spki, keyIdentifier, client, server, ca, dnsNames) {
        let keyUsage = new KeyUsage();
        let extendedKeyUsage = new ExtendedKeyUsage();
        let basicConstraints = new BasicConstraints();
        let extensions = [];

        if (keyIdentifier) {
            extensions.push(Extension.optional(new SubjectKeyIdentifier(keyIdentifier)));
        }

        if (client) {
            keyUsage.flags.digitalSignature = true;
            extendedKeyUsage.usages.push(ExtendedKeyUsage.TLS_WEB_CLIENT_AUTHENTICATION);
        }

        if (server) {
            keyUsage.flags.digitalSignature = true;
            extendedKeyUsage.usages.push(ExtendedKeyUsage.TLS_WEB_SERVER_AUTHENTICATION);
        }

        if (ca) {
            keyUsage.flags.keyCertSign = true;
            basicConstraints.cA = true;
        }

        if (dnsNames?.length) {
            extensions.push(Extension.optional(new SubjectAltName(dnsNames.map(name => GeneralName.dnsName(name)))));
        }

        extensions.push(
            Extension.critical(keyUsage),
            Extension.critical(basicConstraints),
        );

        if (extendedKeyUsage.usages.length) {
            extensions.push(Extension.critical(extendedKeyUsage));
        }


        return new CertificationRequestInfo(
            0,
            Name.parse(subject),
            spki,
            [Attribute.extensionRequests(...extensions)],
        );
    }

    getBytes() {
        return x690.encode(this);
    }


    static forNames(publicKey, commonName, ...dnsNames) {
        return new CertificationRequestInfo(
            0,
            [[RDNAttribute.commonName(commonName)]],
            SubjectPublicKeyInfo.ecPrime256v1(publicKey),
            dnsNames.length
                ? [Attribute.extensionRequests(
                    Extension.critical(
                        new SubjectAltName(dnsNames.map(name => GeneralName.dnsName(name)))
                    )
                )]
                : []
        )
    }

    // https://tools.ietf.org/html/rfc2986#section-4
    static [x690.encoding] = x690.sequence(
        x690.field('version', x690.integer()),
        x690.field('subject', x690.instance(Name)),
        x690.field('subjectPKInfo', x690.instance(SubjectPublicKeyInfo)),
        x690.field('attributes', x690.implicit(0, x690.sequenceOf(x690.instance(Attribute))))
    );

}
export default CertificationRequestInfo;