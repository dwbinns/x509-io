const { field } = require('structured-io');
const x690 = require('x690-io');


class Name {

    static encoding = x690.sequence(
        field('type', x690.oid),
        field('value', x690.anyString)
    );

    // constructor(name, value) {
    //     this.name = name;
    //     this.value = value;
    // }
}

module.exports = Name;