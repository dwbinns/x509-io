// See:
// https://tools.ietf.org/html/rfc5280
// https://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt

const x690=require('x690-io');
const {bytes,read}=require('structured-io');
const fs=require('fs');
const {asBuffer,toHex} = require('buffer-io');

class Name {}
Name.encoding=x690.sequenceOf(x690.setOf(x690.sequence(
    {type:x690.oid},
    {value:x690.anyString}
)));

class Extension {}
Extension.encoding=x690.sequence(
    {extensionID:x690.oid},
    {critical:x690.optional(x690.boolean,false)},
    {extensionValue:x690.octetString},
);

class AlgorithmIdentifier {}
AlgorithmIdentifier.encoding=x690.sequence(
    {algorithm:x690.oid},
);

class Validity {}
Validity.encoding=x690.sequence(
    {notBefore:x690.utcTime},
    {notAfter:x690.utcTime},
);

class SubjectPublicKeyInfo {}
SubjectPublicKeyInfo.encoding=x690.sequence(
    {algorithm:AlgorithmIdentifier},
    {publicKey:x690.bitString},
);

class TBSCertificate {}
TBSCertificate.encoding=x690.sequence(
    {version:x690.explicit(0,x690.integer,0)},
    {serialNumber:x690.integerBytes},
    {signature:AlgorithmIdentifier},
    {issuer:Name},
    {validity:Validity},
    {subject:Name},
    {subjectPublicKeyInfo:SubjectPublicKeyInfo},
    {issuerUniqueID:x690.explicit(1,x690.octetString,null)},
    {subjectUniqueID:x690.explicit(2,x690.octetString,null)},
    {extensions:x690.explicit(3,x690.sequenceOf(Extension),[])},
);


class Certificate {}
Certificate.encoding=x690.sequence(
    {tbsCertificate:TBSCertificate},
    {signatureAlgorithm:AlgorithmIdentifier},
    {signature:x690.bitString},
);


function explainCertificate(certificate) {
    return JSON.stringify(certificate,(key,value)=>{
        if (value && value.type=="Buffer" && value.data) return toHex(value.data);
        if (value instanceof Uint8Array) return toHex(value);
        return value;
    },4);
}

function main(inputFormat, inputFile, outputFormat) {
    if (inputFormat=='pem') {
        let data=new Buffer(fs.readFileSync(inputFile).toString('ascii').replace(/-----.*-----/g,''),'base64');
        //console.log(tohex(data.join(':').match(/(..:){1,16}/g).join('\n'));
        let certificate=read(data, null, Certificate);
        console.log(explainCertificate(certificate));
    } else {
        console.log("x509 pem <certificate.pem>");
    }
}

function pemDecode(type, uint8array) {
    let string = asBuffer(uint8array).toString('ascii');
    let match=string.match(/-----BEGIN (.*)-----/);
    if (!match || match[1]!=type) throw new Error("Incorrect type");
    return new Buffer(string.replace(/-----.*-----/g,''),'base64');
}

function pemEncode(type, uint8array) {
    return `-----BEGIN ${type}-----\n${asBuffer(uint8array).toString('base64')}\n-----END ${type}-----`;
}

if (require.main === module) {
    main(...process.argv.slice(2));
}

module.exports={explainCertificate, Certificate, asBuffer, pemDecode, pemEncode, SubjectPublicKeyInfo};
