const { field } = require('structured-io');
const x690 = require('x690-io');


class Validity {
    static encoding = x690.sequence(
        field('notBefore', x690.utcTime ),
        field('notAfter', x690.utcTime ),
    );
}
module.exports = Validity;
