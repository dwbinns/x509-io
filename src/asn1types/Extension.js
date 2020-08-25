const x690 = require('x690-io');
const SubjectAltName = require('./extensions/SubjectAltName');
const {read, field, instance, optional} = require("structured-io");
const BasicConstraints = require('./extensions/BasicConstraints');
const AuthorityKeyIdentifier = require('./extensions/AuthorityKeyIdentifier');
const SubjectKeyIdentifier = require('./extensions/SubjectKeyIdentifier');




const extensionTypes = [
    SubjectAltName,
    BasicConstraints,
    AuthorityKeyIdentifier,
    SubjectKeyIdentifier,
];

class Extension {
    // https://tools.ietf.org/html/rfc5280#section-4.1

    static encoding = x690.sequence(
        field('extensionID', x690.oid),
        field('critical', optional(false, x690.boolean)),
        field('extensionValue', x690.octetString )
    );

    decodeExtension() {
        let extensionType = extensionTypes.filter(({ID}) => ID == this.extensionID.id).pop();
        if (!extensionType) throw new Error("Unknown extension type " + this.extensionID);
        return read(this.extensionValue, instance(extensionType));
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
            console.log("Failed to decode extension. Ignoring error.");
            console.error(e.stack);
            return {
                ...this,
                error: e.message,
            }
        }
    }
}
module.exports = Extension;
