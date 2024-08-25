import * as x690 from 'x690-io';

class Validity {
    constructor(notBefore, notAfter) {
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }
    static [x690.encoding] = x690.sequence(
        x690.field('notBefore', x690.utcTime() ),
        x690.field('notAfter', x690.utcTime() ),
    );
}
export default Validity;
