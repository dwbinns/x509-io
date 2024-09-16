import * as x690 from 'x690-io';

const transform = {
    Y: "FullYear",
    M: "Month",
    D: "Date",
    h: "Hours",
    m: "Minutes",
    s: "Seconds",
}


function add(date, unit, amount = 1) {
    let newDate = new Date(date);
    newDate[`set${transform[unit]}`](newDate[`get${transform[unit]}`]() + amount);
    return newDate;
}

function parseInterval(interval, start = new Date()) {
    const [, count, unit] = interval.match(/^([0-9]*)([a-zA-Z])$/);
    return add(start, unit, Number(count || "1"));
}

class Validity {
    constructor(notBefore, notAfter) {
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }
    static [x690.encoding] = x690.sequence(
        x690.field('notBefore', x690.utcTime() ),
        x690.field('notAfter', x690.utcTime() ),
    );

    static fromNow(interval) {
        let start = new Date();
        return new Validity(start, parseInterval(interval, start));
    }
}
export default Validity;
