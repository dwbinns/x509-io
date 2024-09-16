import * as x690 from 'x690-io';
import SubjectAltName from '../extensions/SubjectAltName.js';
import BasicConstraints from '../extensions/BasicConstraints.js';
import AuthorityKeyIdentifier from '../extensions/AuthorityKeyIdentifier.js';
import SubjectKeyIdentifier from '../extensions/SubjectKeyIdentifier.js';
import AuthorityInformationAccess from '../extensions/AuthorityInformationAccess.js';
import KeyUsage from '../extensions/KeyUsage.js';
import ExtendedKeyUsage from '../extensions/ExtendedKeyUsage.js';
import CertificatePolicies from '../extensions/CertificatePolicies.js';
import CRLDistributionPoints from '../extensions/CRLDistributionPoints.js';




const extensionTypes = [
    SubjectAltName,
    BasicConstraints,
    AuthorityKeyIdentifier,
    SubjectKeyIdentifier,
    AuthorityInformationAccess,
    KeyUsage,
    ExtendedKeyUsage,
    CertificatePolicies,
    CRLDistributionPoints,
];

class UnknownExtension {
    constructor(bytes) {
        this.bytes = bytes;
    }
}

class Extension {
    // https://tools.ietf.org/html/rfc5280#section-4.1
    constructor(extensionID, critical, extensionValue) {
        this.extensionID = extensionID;
        this.critical = critical;
        this.extensionValue = extensionValue;
    }

    static for(critical, extensionContent) {
        return new Extension(
            new x690.OID(extensionContent.constructor.ID),
            critical,
            x690.encode(extensionContent),
        );
    }

    static critical(extensionContent) {
        return this.for(true, extensionContent);
    }

    static optional(extensionContent) {
        return this.for(false, extensionContent);
    }


    static basicConstraints(cA, pathLenConstraints) {
        return new Extension(
            new x690.OID(BasicConstraints.ID),
            true,
            x690.encode(new BasicConstraints(cA, pathLenConstraints)),
        );
    }

    static [x690.encoding] = x690.sequence(
        x690.field('extensionID', x690.oid()),
        x690.field('critical', x690.optional(x690.boolean(), false)),
        x690.field('extensionValue', x690.octetString())
    );

    // decodeContent() {
    //     return [this.extensionValue, x690.instance(extensionType)];
    // }

    decodeExtension() {
        let extensionType = extensionTypes.find(({ ID }) => ID == this.extensionID.id);
        if (!extensionType) {
            return new UnknownExtension(this.extensionValue);
        }
        //if (!extensionType) throw new Error("Unknown extension type " + this.extensionID);

        //return x690.X690.read(value);
        try {
            return x690.decode(this.extensionValue, extensionType);
        } catch (e) {
            console.error(e);
            return new UnknownExtension(this.extensionValue);
        }
        //return read(this.extensionValue, x690.auto);
    }

    encodeExtension(extensionContent) {
        let extensionType = extensionContent.constructor;
        let extensionOID = extensionTypes.filter(type => type == extensionType).map(({ ID }) => ID).pop();
        if (!extensionOID) throw new Error("Unknown extension type " + extensionType.name);
        this.extensionID = new x690.OID(extensionOID);
        this.extensionValue = x690.encode(extensionContent);
    }

    getDescription() {
        return `${this.critical ? "critical" : "optional"} ${this.extensionID.getDescription()}`;
    }

    getChildren() {
        return Object.entries(this.decodeExtension());
    }

    //get content() { return this.decodeExtension(); }

    // toJSON() {

    //     try {
    //         return {
    //             ...this,
    //             content: this.decodeExtension()
    //         };
    //     } catch (e) {
    //         // console.log("Failed to decode extension. Ignoring error.");
    //         // console.error(e.stack);
    //         return {
    //             ...this,
    //             error: e.message,
    //         }
    //     }
    // }
}
export default Extension;
