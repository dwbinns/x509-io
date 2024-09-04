import RDNAttribute from "./RDNAttribute.js";
import * as x690 from 'x690-io';


export default class Name {
    constructor(rdnSequence) {
        this.rdnSequence = rdnSequence;
    }

    static [x690.encoding] = x690.field("rdnSequence",
        x690.sequenceOf(x690.setOf(x690.instance(RDNAttribute)))
    );

    // https://datatracker.ietf.org/doc/html/rfc4514.html
    // Except with slashes:
    // Eg: /CN=me/C=US
    toString() {
        return "/" + this.rdnSequence.map(attributes => attributes.map(attribute => attribute.toString()).join("+")).join("/")
    }

    static parse(text) {
        // Not complete - should also allow for escaping
        return new Name(
            text.split("/")
                .filter(text => text.trim())
                .map(item => 
                    item.split("+").map(attribute => 
                        RDNAttribute.fromNameAndValue(...attribute.split("="))
                    )
                )
        );
    }

    getDescription() {
        return this.toString();
    }

    getChildren() {
        return [];
    }
}