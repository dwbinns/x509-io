import { Pem } from 'x690-io';
import { toHex } from 'buffer-io';
import { Certificate, CertificationRequest } from 'x509-io';
import { readFile } from "node:fs/promises";
 

function toJSON(certificate) {
        return JSON.stringify(certificate, (key, value) => {
            //  if (value instanceof Date) return "date";
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
        for (let section of Pem.read(await readFile(inputFile, { encoding: 'utf8' })).sections) {
            console.log(section.type);
            if (outputFormat == "explain") {
                section.explain(types);
            } else {
                console.log(toJSON(section.decodeContent(types)));
            }
        }

        //let data = new Buffer(fs.readFileSync(inputFile).toString('ascii').replace(/-----.*-----/g, ''), 'base64');
        //console.log(tohex(data.join(':').match(/(..:){1,16}/g).join('\n'));

    } else {
        console.log("x509 pem <certificate.pem>");
    }
}

await main(...process.argv.slice(2));