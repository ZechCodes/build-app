// Temporary Node trust mitigation until Electron bundles the upstream Node CA fix.
// Public fingerprints: https://emudhra.we-have-a-problem.com/
const { X509Certificate, createHash } = require('node:crypto');
const tls = require('node:tls');

const blockedRoots = new Set([
  "7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d",
  "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
  "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
  "f2edaaff3d9b701fb4d14c9f285f8c0bad90fc3bcc1fa07d47f4718edaba34a5"
]);
const blockedKeys = new Set([
  "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
  "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
  "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
  "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
  "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
  "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
  "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
  "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6"
]);

function filterTrustedCertificates(certificates) {
  return certificates.filter(pem => {
    const cert = new X509Certificate(pem);
    const fingerprint = cert.fingerprint256.replaceAll(':', '').toLowerCase();
    const key = cert.publicKey.export({ type: 'spki', format: 'der' });
    const keyHash = createHash('sha256').update(key).digest('hex');
    return !blockedRoots.has(fingerprint) && !blockedKeys.has(keyHash);
  });
}

function configureNodeTrust() {
  tls.setDefaultCACertificates(filterTrustedCertificates(tls.getCACertificates('default')));
}

module.exports = { configureNodeTrust, filterTrustedCertificates };
