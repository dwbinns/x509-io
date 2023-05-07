// See:
// https://tools.ietf.org/html/rfc5280
// https://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt

Error.stackTraceLimit = Infinity;

import { asBuffer, toHex } from 'buffer-io';
import Certificate from './asn1types/Certificate.js';
import CertificationRequest from './asn1types/csr/CertificationRequest.js';
import CertificationRequestInfo from './asn1types/csr/CertificationRequestInfo.js';


// function pemDecode(type, uint8array) {
//     let string = asBuffer(uint8array).toString('ascii');
//     let match = string.match(/-----BEGIN (.*)-----/);
//     if (!match || match[1] != type) throw new Error("Incorrect type");
//     return new Buffer(string.replace(/-----.*-----/g, ''), 'base64');
// }

// function pemEncode(type, uint8array) {
//     return `-----BEGIN ${type}-----\n${asBuffer(uint8array).toString('base64')}\n-----END ${type}-----`;
// }

export { default as Attribute } from "./asn1types/csr/Attribute.js";
export { default as Extension } from "./asn1types/Extension.js";
export { default as GeneralName } from "./asn1types/GeneralName.js";
export { default as Name } from "./asn1types/Name.js";


export {
    Certificate,
    asBuffer,
    CertificationRequest,
    CertificationRequestInfo,
};
