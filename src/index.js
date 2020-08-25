// See:
// https://tools.ietf.org/html/rfc5280
// https://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt

const { promises: { readFile } } = require('fs');
const { asBuffer, toHex } = require('buffer-io');
const Certificate = require("./asn1types/Certificate");
const CertificationRequest = require("./asn1types/csr/CertificationRequest");
const CertificationRequestInfo = require("./asn1types/csr/CertificationRequestInfo");
const { Pem } = require('x690-io');

Error.stackTraceLimit = Infinity;

function toJSON(certificate) {
    return JSON.stringify(certificate, (key, value) => {

        if (value && value.type == "Buffer" && value.data) return toHex(value.data);
        if (value instanceof Uint8Array) return toHex(value);
        if (typeof value == "bigint") return value.toString();
        //if (!Array.isArray(value) && value && typeof value == "object") return {...value, constructor: value.constructor.name || "?"};
        return value;
    }, 4);
}

const types = [
    ["CERTIFICATE", Certificate],
    ["CERTIFICATE REQUEST", CertificationRequest],
];

async function main(inputFormat, inputFile, outputFormat) {
    if (inputFormat == 'pem') {
        for (let section of Pem.read(await readFile(inputFile, {encoding: 'utf8'})).sections) {
            console.log(section.type);
            let decoded = section.decodeContent(types);
            if (outputFormat == "explain") {
                section.explain(types);
            } else {
                console.log(toJSON(decoded));
            }
        }

        //let data = new Buffer(fs.readFileSync(inputFile).toString('ascii').replace(/-----.*-----/g, ''), 'base64');
        //console.log(tohex(data.join(':').match(/(..:){1,16}/g).join('\n'));

    } else {
        console.log("x509 pem <certificate.pem>");
    }
}

// function pemDecode(type, uint8array) {
//     let string = asBuffer(uint8array).toString('ascii');
//     let match = string.match(/-----BEGIN (.*)-----/);
//     if (!match || match[1] != type) throw new Error("Incorrect type");
//     return new Buffer(string.replace(/-----.*-----/g, ''), 'base64');
// }

// function pemEncode(type, uint8array) {
//     return `-----BEGIN ${type}-----\n${asBuffer(uint8array).toString('base64')}\n-----END ${type}-----`;
// }

if (require.main === module) {
    main(...process.argv.slice(2)).catch(console.error);
}

module.exports = { Certificate, asBuffer, CertificationRequest, CertificationRequestInfo };
