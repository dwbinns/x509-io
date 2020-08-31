Error.stackTraceLimit = Infinity;

let exampleCertificate = `
-----BEGIN CERTIFICATE-----
MIIE+zCCAuOgAwIBAgIJAKa8e8x1L+4JMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xNzA4MDYyMTQwMDdaFw0xODA4MDYyMTQwMDdaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBANGPwj0/zwoKGYT57DVpRQA6dIEzNXjU8XTvBwivaKgAegX41mSdDSLlRPHf
SetWDmvPWHqDVGJcPnXywwJFCdumd84jhmKeT8M3M8BVGMsovazH9iCz+mM0wD6H
eDUUJtkQYu92QDyIoN9vWy+BfY6zrosXnmnm7xudW7TTZTMzUBFZ8V6br4qdtv41
3+Al5MiIc/PUjmjGLyoVuHlHmDPqA5rVXeYIXMnMISdp6Q8dG208dEzY+mxg0as7
oUlcFtKY85EPIYag9QRbQwx4z1UkottZ+cY3MWtZGmPXKaUCL9bvMCz0bD2SLaUR
8t+NO5MNGlrthH8HFJFSw+y8IEo3h/ObH82EwWjeAQomQiQVcb6UP/ulO4XcDBzx
LGw28al7wKmkg4erfRMuZCFZeAKZw4TH5b5LoUGzGUZDhKYL8v9bWYHzty23A0YR
vPJRkPJREhJ0j3y3AjlTauu7/hBuIzrtMh8GF1G1IHrQl7kJgExs00JD+h/tyvwI
TEpBxsGkBhnxxI4kQPOMf1n5mhb9ZKoepMmHijxh9i63tDWwtRqXG+I+GGhWdHQa
9ALHQh9vWYQ7UwphYv5jqotwD9dIgK4Sd3yZyUwoOmA+RTvWH41u4NO1O71iaWkp
2pKj4ji4Y3+TfcYu60q//HogAoa69V5y78mNNg8xmpsz8RB7AgMBAAGjUDBOMB0G
A1UdDgQWBBTkd5LQWXrYPH0L1BCSRZwWdrwtQTAfBgNVHSMEGDAWgBTkd5LQWXrY
PH0L1BCSRZwWdrwtQTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQAp
RRyD4JjewmB158qp3OFRSnFjXCL6AnIluDKgi+kGeVEWbfkTN9NxtO4lse2ZsIP+
u5NMipE1qbE7V/sqjCBnsCSfvhOlEM/VZUU70DgdjHtZ5qfVpOpB6vlCsr+PZ7d4
piAr/yj9aoYnsYD7aX8mu2eK392mdBgiZORRs5uPYfrtdnYwGxeahf2Cu0MtgXKa
PQa3DG4CahY8QLXRVYVrs1SulujBqyFKuT3zJmZ16v13Q3Un4cuqYdX5aTHPs9SL
8XUYsCXyT3szNjxqzbY/EHN3tX3PXRGN42AH4eG+9WST2v8ErT/ERVzdUsnB7JF+
rEMJbeyfgHbpC6SAyKCY9cNi/VxABLKEGwkl4twwSwgTL8yFZLYCVZTGWqUdysID
lLGMj7T8b/78ZZDefn6oeo+k7LaRrt97DIAbFQeMJC3X432dy6ShhB471PKnRSO3
VJItVZsrVlnDtRabNZHcToWw9CK4tNJ12lgyk+wJ5iCaR6lhjFQuXM+uRmVxcb4A
mXDUgwimdadF5F+bjSRUfmPs/SCMTx26zosT8TMobmTMoLPvMqYp+0e6DJ3xcX4o
06a5OjZztAkAwRDb8IgJUQT8KuOIHkMzBiEsCgwNxqfUzJbo6m6xmXclRAF3I+v+
4kD/C8u92mEBlX9abzbUYqk+TBtaID9c7+ilVWUNrg==
-----END CERTIFICATE-----
`;


const {Pem} = require("x690-io");
const Certificate = require("../src/asn1types/Certificate");
const assert = require('assert').strict;



async function main() {
    let pem = Pem.read(exampleCertificate);
    pem.sections[0].explain(Certificate);
    let output = new Pem();
    //console.log("decoded", pem.sections[0].decodeContent(TypedValue));

    //pem.sections[0].explain(Certificate);
    pem.sections.forEach(section => output.addSection(section.type, section.decodeContent(Certificate)));

    //console.log(output.write());

    Pem.read(output.write()).sections[0].explain(Certificate);

    assert.strictEqual(output.write().trim(), exampleCertificate.trim());
    console.log("test passed")
    return 0;
}

main().catch(console.error).then((code = 1) => process.exitCode = code);
