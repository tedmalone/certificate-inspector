const forge = require('node-forge');

function generateKeypair() {
  return forge.pki.rsa.generateKeyPair(2048);
}

function createCert({ subject, issuer, issuerKey, subjectKey, notBefore, notAfter, extensions, serialHex }) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = subjectKey.publicKey;
  cert.serialNumber = serialHex || '01';
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;
  cert.setSubject(subject);
  cert.setIssuer(issuer);
  if (extensions) cert.setExtensions(extensions);
  cert.sign(issuerKey.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

function daysFromNow(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d;
}

console.log('Generating sample certificates (this may take a moment)...');

const leafKeys = generateKeypair();
const oldCAKeys = generateKeypair();
const selfSignedKeys = generateKeypair();
const platformKeys = generateKeypair();
const platformCAKeys = generateKeypair();
const rootCAKeys = generateKeypair();

const validLeafSubject = [{ name: 'commonName', value: 'app.example.com' }];
const intermediateIssuer = [{ name: 'commonName', value: 'Example Intermediate CA' }];

const validLeafPem = createCert({
  subject: validLeafSubject,
  issuer: intermediateIssuer,
  issuerKey: leafKeys,
  subjectKey: leafKeys,
  notBefore: daysFromNow(-90),
  notAfter: daysFromNow(275),
  serialHex: '01',
  extensions: [
    {
      name: 'basicConstraints',
      cA: false,
    },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: 'app.example.com' },
        { type: 2, value: 'www.app.example.com' },
      ],
    },
  ],
});

const expiredSubject = [{ name: 'commonName', value: 'legacy.example.com' }];
const oldCAIssuer = [{ name: 'commonName', value: 'Old CA' }];

const expiredPem = createCert({
  subject: expiredSubject,
  issuer: oldCAIssuer,
  issuerKey: oldCAKeys,
  subjectKey: oldCAKeys,
  notBefore: daysFromNow(-3 * 365),
  notAfter: daysFromNow(-180),
  serialHex: '02',
  extensions: [
    { name: 'basicConstraints', cA: false },
    {
      name: 'subjectAltName',
      altNames: [{ type: 2, value: 'legacy.example.com' }],
    },
  ],
});

const selfSignedSubject = [{ name: 'commonName', value: 'internal.corp' }];

const selfSignedPem = createCert({
  subject: selfSignedSubject,
  issuer: selfSignedSubject,
  issuerKey: selfSignedKeys,
  subjectKey: selfSignedKeys,
  notBefore: daysFromNow(0),
  notAfter: daysFromNow(10 * 365),
  serialHex: '03',
  extensions: [
    { name: 'basicConstraints', cA: true },
  ],
});

const platformSubject = [{ name: 'commonName', value: '*.bigplatform.io' }];
const platformIssuer = [{ name: 'commonName', value: "Let's Platform CA" }];

const multiSANPem = createCert({
  subject: platformSubject,
  issuer: platformIssuer,
  issuerKey: platformCAKeys,
  subjectKey: platformKeys,
  notBefore: daysFromNow(-30),
  notAfter: daysFromNow(60),
  serialHex: '04',
  extensions: [
    { name: 'basicConstraints', cA: false },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: '*.bigplatform.io' },
        { type: 2, value: 'bigplatform.io' },
        { type: 2, value: 'api.bigplatform.io' },
        { type: 2, value: 'admin.bigplatform.io' },
        { type: 2, value: 'status.bigplatform.io' },
      ],
    },
  ],
});

const rootCASubject = [{ name: 'commonName', value: 'Smallstep Demo Root CA' }];

const caCertPem = createCert({
  subject: rootCASubject,
  issuer: rootCASubject,
  issuerKey: rootCAKeys,
  subjectKey: rootCAKeys,
  notBefore: daysFromNow(-2 * 365),
  notAfter: daysFromNow(8 * 365),
  serialHex: '05',
  extensions: [
    { name: 'basicConstraints', cA: true, pathLenConstraint: 0 },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
    },
  ],
});

console.log('Sample certificates generated successfully.');

const samples = [
  {
    id: 'valid-leaf',
    label: 'Valid Leaf — app.example.com',
    description: 'A standard valid leaf certificate for app.example.com with SAN entries.',
    pem: validLeafPem,
  },
  {
    id: 'expired',
    label: 'Expired — legacy.example.com',
    description: 'A certificate that has passed its expiration date.',
    pem: expiredPem,
  },
  {
    id: 'self-signed',
    label: 'Self-Signed — internal.corp',
    description: 'A self-signed certificate with no CA in the chain.',
    pem: selfSignedPem,
  },
  {
    id: 'multi-san',
    label: 'Multi-SAN — *.bigplatform.io',
    description: 'A wildcard certificate with multiple Subject Alternative Names.',
    pem: multiSANPem,
  },
  {
    id: 'ca-cert',
    label: 'CA Certificate — Smallstep Demo Root CA',
    description: 'A Certificate Authority cert with CA:true in basicConstraints.',
    pem: caCertPem,
  },
];

module.exports = { samples };
