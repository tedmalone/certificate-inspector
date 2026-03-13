const express = require('express');
const path = require('path');
const forge = require('node-forge');

const app = express();

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.get('/certs', (req, res) => {
  const { samples } = require('./certs/samples');
  res.json(samples);
});

app.post('/parse', (req, res) => {
  try {
    const pem = req.body.pem;
    if (!pem) {
      return res.status(400).json({ error: 'PEM string is required' });
    }

    const cert = forge.pki.certificateFromPem(pem);
    const now = new Date();
    const notBefore = cert.validity.notBefore;
    const notAfter = cert.validity.notAfter;

    let validityStatus = 'valid';
    if (now < notBefore) validityStatus = 'not-yet-valid';
    if (now > notAfter) validityStatus = 'expired';

    const daysUntilExpiry = Math.floor((notAfter - now) / (1000 * 60 * 60 * 24));

    const getAttr = (dn, attr) => {
      const field = dn.getField(attr);
      return field ? field.value : null;
    };

    const subject = {
      cn: getAttr(cert.subject, 'CN'),
      o: getAttr(cert.subject, 'O'),
    };

    const issuer = {
      cn: getAttr(cert.issuer, 'CN'),
      o: getAttr(cert.issuer, 'O'),
    };

    const sanExt = cert.getExtension('subjectAltName');
    const sans = sanExt ? sanExt.altNames.map(n => n.value) : [];

    const bcExt = cert.getExtension('basicConstraints');
    const basicConstraints = bcExt
      ? { isCA: !!bcExt.cA, pathLen: bcExt.pathLenConstraint !== undefined ? bcExt.pathLenConstraint : null }
      : null;

    const serialNumber = cert.serialNumber;

    let sigAlg = 'sha256WithRSAEncryption';
    if (cert.siginfo && cert.siginfo.algorithmOid) {
      sigAlg = forge.pki.oids[cert.siginfo.algorithmOid] || cert.siginfo.algorithmOid;
    }

    const pubKeyAlg = 'RSA';

    const warnings = [];
    if (validityStatus === 'expired') {
      warnings.push({ type: 'expired', message: 'Certificate has expired' });
    }
    if (validityStatus === 'not-yet-valid') {
      warnings.push({ type: 'not-yet-valid', message: 'Certificate is not yet valid' });
    }
    const isSelfSigned = subject.cn === issuer.cn;
    if (isSelfSigned) {
      warnings.push({ type: 'self-signed', message: 'Certificate is self-signed' });
    }
    const totalDays = Math.floor((notAfter - notBefore) / (1000 * 60 * 60 * 24));
    if (totalDays > 397) {
      warnings.push({ type: 'long-validity', message: `Validity period is ${totalDays} days (exceeds 397-day browser limit)` });
    }
    if (sans.length === 0) {
      warnings.push({ type: 'missing-san', message: 'No Subject Alternative Names (SANs) present' });
    }
    if (basicConstraints && basicConstraints.isCA) {
      warnings.push({ type: 'ca-cert', message: 'This is a CA certificate' });
    }

    res.json({
      subject,
      issuer,
      serialNumber,
      sigAlg,
      pubKeyAlg,
      notBefore,
      notAfter,
      validityStatus,
      daysUntilExpiry,
      sans,
      basicConstraints,
      warnings,
      pem: req.body.pem,
    });
  } catch (e) {
    res.status(400).json({ error: 'Invalid certificate: ' + e.message });
  }
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Running on port ${PORT}`));
}

module.exports = app;
