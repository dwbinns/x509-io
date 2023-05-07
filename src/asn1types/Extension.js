import * as x690 from 'x690-io';import SubjectAltName from './extensions/SubjectAltName.js';
import { write, read, field, instance, optional } from 'structured-io';
import BasicConstraints from './extensions/BasicConstraints.js';
import AuthorityKeyIdentifier from './extensions/AuthorityKeyIdentifier.js';
import SubjectKeyIdentifier from './extensions/SubjectKeyIdentifier.js';
import AuthorityInformationAccess from './extensions/AuthorityInformationAccess.js';




const extensionTypes = [
    SubjectAltName,
    BasicConstraints,
    AuthorityKeyIdentifier,
    SubjectKeyIdentifier,
    AuthorityInformationAccess,
];

class Extension {
    // https://tools.ietf.org/html/rfc5280#section-4.1
    constructor(extensionID, critical, extensionValue) {
        this.extensionID = extensionID;
        this.critical = critical;
        this.extensionValue = extensionValue;
    }

    static subjectAltName(name) {
        return new Extension(
            new x690.OID(SubjectAltName.ID),
            false,
            write(new SubjectAltName(name)),
        );
    }

    static basicConstraints() {
        return new Extension(

        );
    }

    static encoding = x690.sequence(
        field('extensionID', x690.oid),
        field('critical', optional(false, x690.boolean)),
        field('extensionValue', x690.octetString )
    );

    decodeContent() {
        let extensionType = extensionTypes.filter(({ID}) => ID == this.extensionID.id).pop();
        if (!extensionType) throw new Error("Unknown extension type " + this.extensionID);
        return [this.extensionValue, instance(extensionType)];
    }

    decodeExtension() {
        let [value, encoding] = this.decodeContent();
        return read(value, encoding);
        //return read(this.extensionValue, x690.auto);
    }

    encodeExtension(extension) {
        let extensionType = extension.constructor;
        let extensionOID = extensionTypes.filter(type => type == extensionType).map(({ID}) => ID).pop();
        if (!extensionOID) throw new Error("Unknown extension type " + extensionType.name);
        this.extensionID = new OID(extensionOID);
        this.extensionValue = write(extension);
    }



    toJSON() {

        try {
            return {
                ...this,
                content: this.decodeExtension()
            };
        } catch (e) {
            // console.log("Failed to decode extension. Ignoring error.");
            // console.error(e.stack);
            return {
                ...this,
                error: e.message,
            }
        }
    }
}
export default Extension;