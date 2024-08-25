import * as x690 from 'x690-io';
import GeneralName from '../certificate/GeneralName.js';
import RDNAttribute from '../certificate/RDNAttribute.js';

class DistributionPoint {
    static [x690.encoding] = x690.sequence(
        x690.field("distributionPoint", x690.optional(x690.explicit(0, x690.choice(
            x690.implicit(0, x690.sequenceOf(x690.instance(GeneralName))),
            x690.implicit(1, x690.setOf(x690.instance(RDNAttribute))),
        )))),
        x690.field("reasons", x690.optional(x690.explicit(1, x690.bitString()))),
        x690.field("cRLIssuer", x690.optional(x690.explicit(2, x690.sequenceOf(x690.instance(GeneralName))))),
    );
}

export default class CRLDistributionPoints {
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.13
    static ID = "2.5.29.31";
    static [x690.encoding] = x690.field("crlDistributionPoints", x690.sequenceOf(x690.instance(DistributionPoint)));
};

