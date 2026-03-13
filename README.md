# 🔐 Certificate Inspector

A lightweight developer tool for inspecting X.509 certificates. Select from 5 built-in sample certificates to explore certificate fields, validity status, warnings, and raw PEM data — with zero setup.

Built to demonstrate Smallstep's certificate lifecycle concepts.

## Quick Start

```bash
npm install
npm start
```

Then open http://localhost:3000

## Sample Certificates

| # | Label | Demonstrates |
|---|-------|-------------|
| 1 | Valid Leaf — app.example.com | Normal leaf cert, standard validity |
| 2 | Expired — legacy.example.com | Certificate past its expiration date |
| 3 | Self-Signed — internal.corp | No CA in the chain; common for internal tools |
| 4 | Multi-SAN — *.bigplatform.io | Multiple Subject Alternative Names |
| 5 | CA Certificate — Smallstep Demo Root CA | Certificate Authority cert with CA:true |

All sample certificates are generated locally at startup using `node-forge`. No external services, uploads, or API keys required.

## Tech Stack

- Node.js + Express (backend)
- node-forge (X.509 parsing and generation)
- Vanilla JS + CSS (frontend)

## Running Tests

```bash
npm test
```

Tests use [Jest](https://jestjs.io/) and [Supertest](https://github.com/ladjs/supertest) for integration testing against the Express app directly (no live server required).
