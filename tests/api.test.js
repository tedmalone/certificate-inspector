const request = require('supertest');
const app = require('../server');

describe('GET /certs', () => {
  it('returns 5 sample certificates', async () => {
    const res = await request(app).get('/certs');
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(5);
    res.body.forEach(cert => {
      expect(cert).toHaveProperty('id');
      expect(cert).toHaveProperty('label');
      expect(cert).toHaveProperty('pem');
    });
  });
});

describe('POST /parse', () => {
  let certs;

  beforeAll(async () => {
    const res = await request(app).get('/certs');
    certs = res.body;
  });

  it('parses a valid cert and returns all required fields', async () => {
    const pem = certs.find(c => c.id === 'valid-leaf').pem;
    const res = await request(app).post('/parse').send({ pem });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('subject');
    expect(res.body).toHaveProperty('issuer');
    expect(res.body).toHaveProperty('validityStatus');
    expect(res.body).toHaveProperty('daysUntilExpiry');
    expect(res.body).toHaveProperty('warnings');
    expect(res.body).toHaveProperty('sans');
    expect(res.body).toHaveProperty('serialNumber');
    expect(res.body).toHaveProperty('sigAlg');
    expect(res.body).toHaveProperty('pubKeyAlg');
    expect(res.body).toHaveProperty('notBefore');
    expect(res.body).toHaveProperty('notAfter');
    expect(res.body).toHaveProperty('basicConstraints');
  });

  it('marks expired cert as expired', async () => {
    const pem = certs.find(c => c.id === 'expired').pem;
    const res = await request(app).post('/parse').send({ pem });
    expect(res.status).toBe(200);
    expect(res.body.validityStatus).toBe('expired');
    expect(res.body.warnings.some(w => w.type === 'expired')).toBe(true);
  });

  it('detects self-signed cert', async () => {
    const pem = certs.find(c => c.id === 'self-signed').pem;
    const res = await request(app).post('/parse').send({ pem });
    expect(res.status).toBe(200);
    expect(res.body.warnings.some(w => w.type === 'self-signed')).toBe(true);
  });

  it('detects CA cert', async () => {
    const pem = certs.find(c => c.id === 'ca-cert').pem;
    const res = await request(app).post('/parse').send({ pem });
    expect(res.status).toBe(200);
    expect(res.body.basicConstraints.isCA).toBe(true);
    expect(res.body.warnings.some(w => w.type === 'ca-cert')).toBe(true);
  });

  it('returns 400 for invalid PEM', async () => {
    const res = await request(app).post('/parse').send({ pem: 'not-a-cert' });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });
});
