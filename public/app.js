let certs = [];
let activeId = null;

async function init() {
  try {
    const res = await fetch('/certs');
    if (!res.ok) throw new Error('Failed to load certs');
    certs = await res.json();
    renderSelector();
    if (certs.length > 0) {
      loadCert(certs[0]);
    }
  } catch (e) {
    document.getElementById('loading-state').innerHTML =
      '<span style="color:#ef4444">Failed to load certificates. Please refresh.</span>';
  }
}

function renderSelector() {
  const container = document.getElementById('cert-selector');
  container.innerHTML = '';
  certs.forEach(cert => {
    const btn = document.createElement('button');
    btn.className = 'cert-btn' + (cert.id === activeId ? ' active' : '');
    btn.textContent = cert.label;
    btn.dataset.id = cert.id;
    btn.addEventListener('click', () => {
      if (cert.id !== activeId) {
        loadCert(cert);
      }
    });
    container.appendChild(btn);
  });
}

async function loadCert(cert) {
  activeId = cert.id;
  renderSelector();

  const loadingEl = document.getElementById('loading-state');
  const contentEl = document.getElementById('detail-content');

  loadingEl.style.display = 'flex';
  contentEl.style.display = 'none';
  contentEl.style.opacity = '0';

  try {
    const res = await fetch('/parse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pem: cert.pem }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Parse error');
    }
    renderDetail(data);
  } catch (e) {
    loadingEl.innerHTML = `<span style="color:#ef4444">Error: ${e.message}</span>`;
  }
}

function fmt(date) {
  if (!date) return '—';
  const d = new Date(date);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

function renderDetail(data) {
  const loadingEl = document.getElementById('loading-state');
  const contentEl = document.getElementById('detail-content');

  // Status badge
  const badge = document.getElementById('status-badge');
  const statusLabel = document.getElementById('status-label');
  const expiryInfo = document.getElementById('expiry-info');

  badge.className = 'status-badge ' + data.validityStatus;
  const statusMap = {
    valid: '🟢 Valid',
    expired: '🔴 Expired',
    'not-yet-valid': '🟡 Not Yet Valid',
  };
  badge.textContent = statusMap[data.validityStatus] || data.validityStatus;
  statusLabel.textContent = certs.find(c => c.id === activeId)?.label || '';

  if (data.daysUntilExpiry >= 0) {
    expiryInfo.textContent = `Expires in ${data.daysUntilExpiry} day${data.daysUntilExpiry !== 1 ? 's' : ''}`;
  } else {
    expiryInfo.textContent = `Expired ${Math.abs(data.daysUntilExpiry)} day${Math.abs(data.daysUntilExpiry) !== 1 ? 's' : ''} ago`;
  }

  // Identity fields
  renderFieldRows('identity-fields', [
    {
      key: 'Subject CN',
      value: data.subject?.cn || '—',
      desc: 'The domain or entity this certificate was issued to',
    },
    {
      key: 'Subject Org',
      value: data.subject?.o || '—',
    },
    {
      key: 'Issuer CN',
      value: data.issuer?.cn || '—',
      desc: 'The Certificate Authority that signed this cert',
    },
    {
      key: 'Issuer Org',
      value: data.issuer?.o || '—',
    },
  ]);

  // Validity fields
  renderFieldRows('validity-fields', [
    {
      key: 'Valid From',
      value: fmt(data.notBefore),
      desc: 'The window during which this certificate is trusted',
    },
    {
      key: 'Valid To',
      value: fmt(data.notAfter),
    },
    {
      key: 'Status',
      value: data.validityStatus,
    },
  ]);

  // Technical fields
  renderFieldRows('technical-fields', [
    {
      key: 'Serial Number',
      value: data.serialNumber || '—',
      desc: 'Unique identifier assigned by the issuing CA',
    },
    {
      key: 'Signature Alg',
      value: data.sigAlg || '—',
      desc: 'Cryptographic algorithm used to sign the cert',
    },
    {
      key: 'Public Key Alg',
      value: data.pubKeyAlg || '—',
      desc: "Algorithm used for the certificate's public key",
    },
  ]);

  // SANs
  const sanCard = document.getElementById('san-card');
  const sanList = document.getElementById('san-list');
  if (data.sans && data.sans.length > 0) {
    sanCard.style.display = 'block';
    sanList.innerHTML = data.sans.map(san => `
      <li class="san-item">
        <span class="san-prefix">DNS</span>
        <span class="san-value">${escHtml(san)}</span>
      </li>
    `).join('');
  } else {
    sanCard.style.display = 'none';
  }

  // Basic Constraints
  const bcCard = document.getElementById('bc-card');
  if (data.basicConstraints) {
    bcCard.style.display = 'block';
    renderFieldRows('bc-fields', [
      { key: 'Is CA', value: data.basicConstraints.isCA ? 'Yes' : 'No' },
      {
        key: 'Path Length',
        value: data.basicConstraints.pathLen !== null ? String(data.basicConstraints.pathLen) : '—',
      },
    ]);
  } else {
    bcCard.style.display = 'none';
  }

  // Warnings
  const warningsSection = document.getElementById('warnings-section');
  const warningsList = document.getElementById('warnings-list');
  const warningIconMap = {
    expired: '🔴',
    'not-yet-valid': '🔴',
    'self-signed': '⚠️',
    'missing-san': '⚠️',
    'long-validity': '🟠',
    'ca-cert': 'ℹ️',
  };

  if (data.warnings && data.warnings.length > 0) {
    warningsList.innerHTML = data.warnings.map(w => `
      <div class="warning-card ${escHtml(w.type)}">
        <span class="warning-icon">${warningIconMap[w.type] || '⚠️'}</span>
        <span>${escHtml(w.message)}</span>
      </div>
    `).join('');
  } else {
    warningsList.innerHTML = '<div class="no-warnings">✅ No warnings for this certificate.</div>';
  }

  // Raw PEM
  document.getElementById('raw-pem').textContent = data.pem || '';

  // Show content
  loadingEl.style.display = 'none';
  contentEl.style.display = 'block';
  requestAnimationFrame(() => {
    contentEl.style.opacity = '1';
  });
}

function renderFieldRows(tbodyId, fields) {
  const tbody = document.getElementById(tbodyId);
  tbody.innerHTML = fields.map(f => `
    <tr>
      <td class="field-key">${escHtml(f.key)}</td>
      <td class="field-value">
        ${escHtml(f.value)}
        ${f.desc ? `<span class="field-desc">${escHtml(f.desc)}</span>` : ''}
      </td>
    </tr>
  `).join('');
}

function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

document.addEventListener('DOMContentLoaded', init);
