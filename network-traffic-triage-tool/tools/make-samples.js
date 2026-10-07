/* ============================================================================
   Generateur des captures CSV de demonstration (fictives)
   ----------------------------------------------------------------------------
   Ce script sert uniquement a FABRIQUER les fichiers d'exemple.
   Il n'est pas necessaire pour utiliser l'application.

       node tools/make-samples.js
   ============================================================================ */
'use strict';
const fs = require('fs');
const path = require('path');

const HEADER = 'No.,Time,Source,Destination,Protocol,Length,Info';
const outDir = path.join(__dirname, '..', 'samples');

function build(rows) {
  const lines = [HEADER];
  let t = 0.000000;
  rows.forEach((r, i) => {
    t += r.dt;
    lines.push([
      i + 1,
      t.toFixed(6),
      r.src,
      r.dst,
      r.proto,
      r.len,
      '"' + r.info.replace(/"/g, '""') + '"'
    ].join(','));
  });
  return lines.join('\n') + '\n';
}

/* ---------------- 1. Reseau normal ---------------- */
const normal = [];
const hosts = ['192.168.1.10', '192.168.1.20'];
const sites = ['203.0.113.10', '203.0.113.24', '198.51.100.7'];
hosts.forEach((h, hi) => {
  for (let i = 0; i < 4; i++) {
    normal.push({ dt: 0.12, src: h, dst: '192.168.1.1', proto: 'DNS', len: 74,
      info: 'Standard query 0x' + (1000 + hi * 10 + i).toString(16) + ' A www.exemple-entreprise.test' });
    normal.push({ dt: 0.09, src: '192.168.1.1', dst: h, proto: 'DNS', len: 90,
      info: 'Standard query response 0x' + (1000 + hi * 10 + i).toString(16) + ' A www.exemple-entreprise.test A ' + sites[i % 3] });
    normal.push({ dt: 0.05, src: h, dst: sites[i % 3], proto: 'TCP', len: 66,
      info: (40000 + hi * 100 + i) + ' \u2192 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM' });
    normal.push({ dt: 0.04, src: sites[i % 3], dst: h, proto: 'TCP', len: 66,
      info: '443 \u2192 ' + (40000 + hi * 100 + i) + ' [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460' });
    normal.push({ dt: 0.03, src: h, dst: sites[i % 3], proto: 'TLSv1.3', len: 571,
      info: 'Application Data, Application Data' });
  }
});
normal.push({ dt: 0.20, src: '192.168.1.20', dst: '192.168.1.1', proto: 'ARP', len: 42,
  info: 'Who has 192.168.1.1? Tell 192.168.1.20' });

/* ---------------- 2. Scan d'hotes / de ports ---------------- */
const scan = [];
for (let i = 0; i < 24; i++) {
  scan.push({ dt: 0.01, src: '192.168.1.25', dst: '192.168.1.' + (40 + i), proto: 'TCP', len: 58,
    info: (45000 + i) + ' \u2192 ' + [22, 80, 139, 445, 3389][i % 5] + ' [SYN] Seq=0 Win=1024 Len=0' });
}
for (let i = 0; i < 22; i++) {
  scan.push({ dt: 0.008, src: '192.168.1.25', dst: '192.168.1.5', proto: 'TCP', len: 54,
    info: (46000 + i) + ' \u2192 ' + (1000 + i) + ' [SYN] Seq=0 Win=1024 Len=0' });
}
scan.push({ dt: 0.02, src: '192.168.1.25', dst: '192.168.1.5', proto: 'TCP', len: 60,
  info: '46000 \u2192 1000 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0' });
scan.push({ dt: 0.02, src: '192.168.1.25', dst: '192.168.1.5', proto: 'TCP', len: 60,
  info: '46001 \u2192 1001 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0' });

/* ---------------- 3. Activite ICMP elevee (balayage) ---------------- */
const icmp = [];
for (let i = 0; i < 45; i++) {
  icmp.push({ dt: 0.02, src: '192.168.1.30', dst: '192.168.1.' + (1 + (i % 60)), proto: 'ICMP', len: 74,
    info: 'Echo (ping) request  id=0x0' + (i % 9) + ', seq=' + (i + 1) + '/1152, ttl=64' });
}
for (let i = 0; i < 12; i++) {
  icmp.push({ dt: 0.05, src: '192.168.1.1', dst: '192.168.1.30', proto: 'ICMP', len: 74,
    info: 'Echo (ping) reply    id=0x0' + (i % 9) + ', seq=' + (i + 1) + '/1152, ttl=255' });
}

/* ---------------- 4. Capture mixte (demonstration SOC) ---------------- */
const mixed = [];
for (let i = 0; i < 62; i++) {
  mixed.push({ dt: 0.02, src: '192.168.1.25', dst: '203.0.113.55', proto: 'TCP', len: 1500,
    info: (50000 + i) + ' \u2192 443 [ACK] Seq=' + (i * 1460) + ' Win=64240 Len=1460' });
}
for (let i = 0; i < 38; i++) {
  mixed.push({ dt: 0.03, src: '192.168.1.40', dst: '192.168.1.1', proto: 'DNS', len: 78,
    info: 'Standard query 0x' + (2000 + i).toString(16) + ' A cdn' + i + '.exemple-service.test' });
}
for (let i = 0; i < 34; i++) {
  mixed.push({ dt: 0.02, src: '192.168.1.30', dst: '198.51.100.' + (10 + (i % 12)), proto: 'ICMP', len: 74,
    info: 'Echo (ping) request  id=0x0101, seq=' + (i + 1) + '/256, ttl=64' });
}
for (let i = 0; i < 14; i++) {
  mixed.push({ dt: 0.01, src: '192.168.1.77', dst: '192.168.1.90', proto: 'TCP', len: 54,
    info: (60000 + i) + ' \u2192 ' + (20 + i) + ' [SYN] Seq=0 Win=1024 Len=0' });
}
for (let i = 0; i < 6; i++) {
  mixed.push({ dt: 0.30, src: '192.168.1.10', dst: '192.168.1.1', proto: 'DNS', len: 74,
    info: 'Standard query 0x' + (3000 + i).toString(16) + ' A www.exemple-entreprise.test' });
}

const files = {
  'normal-network.csv': build(normal),
  'host-scan.csv': build(scan),
  'icmp-sweep.csv': build(icmp),
  'mixed-soc-sample.csv': build(mixed)
};

if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
for (const name of Object.keys(files)) {
  fs.writeFileSync(path.join(outDir, name), files[name], 'utf8');
  const n = files[name].trim().split('\n').length - 1;
  console.log(name + ' : ' + n + ' paquets');
}
