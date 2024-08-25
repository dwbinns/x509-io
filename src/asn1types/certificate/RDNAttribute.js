import * as x690 from 'x690-io';



export default class RDNAttribute {

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.4
    static [x690.encoding] = x690.sequence(
        x690.field('type', x690.oid()),
        x690.field('value', x690.anyString())
    );

    constructor(type, value) {
        this.type = type;
        this.value = value;
    }

    static commonName(value) {
        return new RDNAttribute(new x690.OID("2.5.4.3"), value);
    }

    toString() {
        return `${this.type.short || this.type.id}=${this.value.split().map(char => '"+,;<>\\/'.includes(char) ? `\\${char}` : char).join("")}`;
    }

    getDescription() {
        return `${this.type.name}: ${this.value}`;
    }

    getChildren() { return []; }
}