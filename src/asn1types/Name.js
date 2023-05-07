import { field } from 'structured-io';
import * as x690 from 'x690-io';



class Name {

    // https://tools.ietf.org/html/rfc5280#section-4.2.1.4
    static encoding = x690.sequence(
        field('type', x690.oid),
        field('value', x690.anyString)
    );

    constructor(type, value) {
        this.type = type;
        this.value = value;
    }

    static commonName(value) {
        return new Name(new x690.OID("2.5.4.3"), value);
    }

    // constructor(name, value) {
    //     this.name = name;
    //     this.value = value;
    // }
}

export default Name;