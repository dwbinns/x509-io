//@ts-check
import * as x690 from 'x690-io';
import AlgorithmIdentifier from './AlgorithmIdentifier.js';
import Extension from './Extension.js';
import RDNAttribute from './RDNAttribute.js';
import SubjectPublicKeyInfo from './SubjectPublicKeyInfo.js';
import Validity from './Validity.js';
import Name from './Name.js';
import KeyUsage from '../extensions/KeyUsage.js';
import ExtendedKeyUsage from '../extensions/ExtendedKeyUsage.js';
import SubjectAltName from '../extensions/SubjectAltName.js';
import GeneralName from './GeneralName.js';
import BasicConstraints from '../extensions/BasicConstraints.js';
import SubjectKeyIdentifier from '../extensions/SubjectKeyIdentifier.js';
import AuthorityKeyIdentifier from '../extensions/AuthorityKeyIdentifier.js';

const v3 = 2;

class TBSCertificate {

    version = v3;
    extensions = [];
    subjectKeyIdentifier;

    constructor(init) {
        if (init) Object.assign(this, init);
    }


    getExtension(extensionType) {
        return this.extensions?.find(extension => extension.extensionID.id == extensionType.ID)?.decodeExtension();
    }

    updateExtension(extensionType, critical, callback) {
        let extension = this.extensions?.find(extension => extension.extensionID.id == extensionType.ID);
        if (!extension) {
            extension = Extension.optional(new extensionType());
            this.extensions ||= [];
            this.extensions.push(extension);
        }
        extension.critical ||= critical;
        this.extensions?.forEach(extension => {
            let decoded = extension.decodeExtension();
            if (extension.extensionID.id == extensionType.ID) callback(decoded);
            extension.encodeExtension(decoded);
        });
    }

    storeExtension(critical, content) {
        this.extensions.push(Extension.for(critical, content));
    }

    // https://tools.ietf.org/html/rfc5280#section-4.1.1.1
    static [x690.encoding] = x690.sequence(
        x690.field('version', x690.optional(x690.explicit(0, x690.integer()), 0)),
        x690.field('serialNumber', x690.bigInt()),
        x690.field('signature', x690.instance(AlgorithmIdentifier)),
        x690.field('issuer', x690.instance(Name)),
        x690.field('validity', x690.instance(Validity)),
        x690.field('subject', x690.instance(Name)),
        x690.field('subjectPublicKeyInfo', x690.instance(SubjectPublicKeyInfo)),
        x690.field('issuerUniqueID', x690.optional(x690.explicit(1, x690.octetString()))),
        x690.field('subjectUniqueID', x690.optional(x690.explicit(2, x690.octetString()))),
        x690.field('extensions', x690.explicit(3, x690.sequenceOf(x690.instance(Extension))))
    );

    static create(authorityCertificate, subject, spki, keyIdentifier, serialNumber, validity, client, server, ca, dnsNames) {
        let tbsCertificate = new TBSCertificate({
            serialNumber,
        });

        tbsCertificate.setValidityDuration(validity);
        tbsCertificate.setSubject(subject, spki, keyIdentifier);
        if (!authorityCertificate) tbsCertificate.setSelfSigned();
        else tbsCertificate.setAuthority(authorityCertificate);

        if (client) tbsCertificate.setWebClient();
        if (server) tbsCertificate.setWebServer(dnsNames);
        if (ca) tbsCertificate.setCA();
        return tbsCertificate;
    }

    // static create({subject, serialNumber = 1n, authorityCertificate, subjectPublicKey, dnsNames, isCA, isClient}) {
    //     let subjectNames = Name.parse(subject);
    //     let authorityKeyIdentifier = authorityCertificate?.
    //     return new TBSCertificate({
    //         version: 2,
    //         serialNumber: BigInt(serialNumber),
    //         signature: signatureAlgorithmID,
    //         issuer: issuerNames,
    //         validity: new Validity(
    //             new Date(),
    //             parseInterval(validity),
    //         ),
    //         subject: subjectNames,
    //         subjectPublicKeyInfo: subjectPublicKey,
    //         extensions: [
    //             Extension.optional(new SubjectKeyIdentifier(subjectKeyIdentifier)),
    //             Extension.optional(new AuthorityKeyIdentifier(authorityKeyIdentifier)),
    //             Extension.critical(new KeyUsage({
    //                 digitalSignature: isClient || !!dnsNames.length,
    //                 keyCertSign: !!isCA,
    //             })),
    //             dnsNames.length ? Extension.optional(new SubjectAltName(dnsNames.map(name => GeneralName.dnsName(name)))) : null,
    //             Extension.critical(new BasicConstraints(isCA)),
    //             (dnsNames.length || isClient) && Extension.critical(new ExtendedKeyUsage([
    //                 dnsNames.length && ExtendedKeyUsage.TLS_WEB_SERVER_AUTHENTICATION,
    //                 isClient && ExtendedKeyUsage.TLS_WEB_CLIENT_AUTHENTICATION,
    //             ].filter(Boolean))),
    //         ].filter(Boolean),
    //     });
    // }

    setSigningAlgorithmId(algorithmID) {
        this.signature = algorithmID;
    }

    setSubject(input, spki, keyIdentifier) {
        this.subject = Name.parse(input);
        this.subjectPublicKeyInfo = spki;
        this.storeExtension(false, new SubjectKeyIdentifier(keyIdentifier));
    }

    setCA(pathLenConstraint) {
        this.updateExtension(KeyUsage, true, keyUsage => keyUsage.flags.keyCertSign = true);
        this.updateExtension(BasicConstraints, true, basicConstraints => {
            basicConstraints.cA = true;
            basicConstraints.pathLenConstraint = pathLenConstraint;
        });
    }

    setWebServer(dnsNames) {
        this.updateExtension(KeyUsage, true, keyUsage => keyUsage.flags.digitalSignature = true);
        this.updateExtension(ExtendedKeyUsage, true, e => e.usages.push(ExtendedKeyUsage.TLS_WEB_SERVER_AUTHENTICATION));
        this.storeExtension(false, new SubjectAltName(dnsNames.map(name => GeneralName.dnsName(name))));
    }

    setWebClient() {
        this.updateExtension(KeyUsage, true, keyUsage => keyUsage.flags.digitalSignature = true);
        this.updateExtension(ExtendedKeyUsage, true, e => e.usages.push(ExtendedKeyUsage.TLS_WEB_CLIENT_AUTHENTICATION));
    }

    setValidityDuration(duration) {
        this.validity = Validity.fromNow(duration);
    }

    setSelfSigned() {
        this.storeExtension(false, new AuthorityKeyIdentifier(this.getExtension(SubjectKeyIdentifier).keyIdentifier));
        this.issuer = this.subject;
    }

    setAuthority(authorityCertificate) {
        this.storeExtension(false, new AuthorityKeyIdentifier(authorityCertificate.tbsCertificate.getExtension(SubjectKeyIdentifier).keyIdentifier));
        this.issuer = authorityCertificate.tbsCertificate.subject;
    }

    getBytes() {
        return x690.encode(this);
    }
}
export default TBSCertificate;
