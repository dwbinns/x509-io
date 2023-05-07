import { field } from 'structured-io';
import * as x690 from 'x690-io';

class Validity {
    static encoding = x690.sequence(
        field('notBefore', x690.utcTime ),
        field('notAfter', x690.utcTime ),
    );
}
export default Validity;
