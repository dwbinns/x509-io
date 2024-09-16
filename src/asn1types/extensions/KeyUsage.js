import * as x690 from 'x690-io';

const names = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];

export default class KeyUsage {
    constructor(flags = {}) {
        this.flags = flags;
    }

    // getUsages() {
    //     return bitNames.filter((name, index) => (1 << index) & this.bits)
    // }

    // getDescription() {
    //     return this.getUsages().join(",");
    // }

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.3
    static ID = "2.5.29.15";
    static [x690.encoding] = x690.field("flags", x690.flags(names));
};

