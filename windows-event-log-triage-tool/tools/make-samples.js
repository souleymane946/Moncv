/* ============================================================================
   Generateur des journaux de demonstration (fictifs)
   ----------------------------------------------------------------------------
   Sert uniquement a FABRIQUER les fichiers d'exemple.
   Non necessaire pour utiliser l'application.

       node tools/make-samples.js
   ============================================================================ */
'use strict';
const fs = require('fs');
const path = require('path');

const HEADER = 'Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message';
const outDir = path.join(__dirname, '..', 'samples');

function q(v) { return '"' + String(v).replace(/"/g, '""') + '"'; }

function build(events) {
  const lines = [HEADER];
  for (const e of events) {
    lines.push([e.level, e.time, e.source, e.id, e.task, e.user, e.computer, e.keywords, q(e.message)].join(','));
  }
  return lines.join('\n') + '\n';
}

/* Horodatage au format francais jour/mois/annee (volontairement ambigu). */
function t(day, h, m, s) {
  const p = (n) => String(n).padStart(2, '0');
  return p(day) + '/10/2025 ' + p(h) + ':' + p(m) + ':' + p(s || 0);
}

function msg4624(user, ip, computer, type) {
  return 'An account was successfully logged on.\n\n' +
    'Subject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\t' + computer + '$\n' +
    'Logon Information:\n\tLogon Type:\t\t' + type + '\n' +
    'New Logon:\n\tSecurity ID:\t\tS-1-5-21-0000\n\tAccount Name:\t\t' + user + '\n' +
    'Network Information:\n\tWorkstation Name:\t' + computer + '\n' +
    '\tSource Network Address:\t' + ip;
}

function msg4625(user, ip, computer, type) {
  return 'An account failed to log on.\n\n' +
    'Subject:\n\tAccount Name:\t\t' + computer + '$\n' +
    'Logon Type:\t\t' + type + '\n' +
    'Account For Which Logon Failed:\n\tAccount Name:\t\t' + user + '\n' +
    'Network Information:\n\tWorkstation Name:\t' + computer + '\n' +
    '\tSource Network Address:\t' + ip;
}

function msg4720(newUser, actor, computer) {
  return 'A user account was created.\n\n' +
    'Subject:\n\tAccount Name:\t\t' + actor + '\n' +
    'New Account:\n\tAccount Name:\t\t' + newUser + '\n' +
    'Computer:\t' + computer;
}

function msg4726(target, actor) {
  return 'A user account was deleted.\n\n' +
    'Subject:\n\tAccount Name:\t\t' + actor + '\n' +
    'Target Account:\n\tAccount Name:\t\t' + target;
}

function msg4732(target, group, actor) {
  return 'A member was added to a security-enabled local group.\n\n' +
    'Subject:\n\tAccount Name:\t\t' + actor + '\n' +
    'Member:\n\tAccount Name:\t\t' + target + '\n' +
    'Group:\n\tGroup Name:\t\t' + group;
}

function msg4728(target, group, actor) {
  return 'A member was added to a security-enabled global group.\n\n' +
    'Subject:\n\tAccount Name:\t\t' + actor + '\n' +
    'Member:\n\tAccount Name:\t\t' + target + '\n' +
    'Group:\n\tGroup Name:\t\t' + group;
}

function msg1102(actor) {
  return 'The audit log was cleared.\n\n' +
    'Subject:\n\tAccount Name:\t\t' + actor + '\n' +
    'Computer:\tSRV-AD-01';
}

function msg4688(proc, parent, user) {
  return 'A new process has been created.\n\n' +
    'New Process Name:\t\t' + proc + '\n' +
    'Creator Process Name:\t' + parent + '\n' +
    'Process Command Line:\t' + proc + '\n' +
    'Account Name:\t\t' + user;
}

function msg7045(service, user) {
  return 'A service was installed in the system.\n\n' +
    'Service Name:\t' + service + '\n' +
    'Service File Name:\tC:\\Program Files\\Exemple\\' + service + '.exe\n' +
    'Account Name:\t' + user;
}

function msg4104(text, user) {
  return 'Creating Scriptblock text (1 of 1):\n' + text + '\n' +
    'Account Name:\t' + user;
}

/* ---------------- 1. Activite Windows normale ---------------- */
const normal = [];
for (let i = 0; i < 5; i++) {
  normal.push({ level: 'Information', time: t(6, 8, 5 + i, 10), source: 'Microsoft-Windows-Security-Auditing',
    id: 4624, task: 'Logon', user: 'mgarcia', computer: 'PC-COMPTA-01', keywords: 'Audit Success',
    message: msg4624('mgarcia', '192.168.10.40', 'PC-COMPTA-01', '2') });
  normal.push({ level: 'Information', time: t(6, 8, 6 + i, 40), source: 'Microsoft-Windows-Security-Auditing',
    id: 4688, task: 'Process Creation', user: 'mgarcia', computer: 'PC-COMPTA-01', keywords: 'Audit Success',
    message: msg4688('C:\\Program Files\\Microsoft Office\\WINWORD.EXE', 'C:\\Windows\\explorer.exe', 'mgarcia') });
}
normal.push({ level: 'Information', time: t(6, 9, 12, 5), source: 'Microsoft-Windows-Security-Auditing',
  id: 4634, task: 'Logoff', user: 'mgarcia', computer: 'PC-COMPTA-01', keywords: 'Audit Success',
  message: 'An account was logged off.\n\nAccount Name:\t\tmgarcia' });
normal.push({ level: 'Information', time: t(6, 10, 3, 22), source: 'Microsoft-Windows-Security-Auditing',
  id: 4624, task: 'Logon', user: 'svc-backup', computer: 'SRV-FICHIER-02', keywords: 'Audit Success',
  message: msg4624('svc-backup', '10.0.0.5', 'SRV-FICHIER-02', '5') });
normal.push({ level: 'Information', time: t(6, 11, 30, 0), source: 'Microsoft-Windows-Security-Auditing',
  id: 4672, task: 'Special Logon', user: 'admin.local', computer: 'SRV-AD-01', keywords: 'Audit Success',
  message: 'Special privileges assigned to new logon.\n\nAccount Name:\t\tadmin.local' });
normal.push({ level: 'Error', time: t(6, 14, 2, 11), source: 'Microsoft-Windows-Security-Auditing',
  id: 4625, task: 'Logon', user: 'mgarcia', computer: 'PC-COMPTA-01', keywords: 'Audit Failure',
  message: msg4625('mgarcia', '192.168.10.40', 'PC-COMPTA-01', '2') });
normal.push({ level: 'Information', time: t(6, 14, 2, 30), source: 'Microsoft-Windows-Security-Auditing',
  id: 4624, task: 'Logon', user: 'mgarcia', computer: 'PC-COMPTA-01', keywords: 'Audit Success',
  message: msg4624('mgarcia', '192.168.10.40', 'PC-COMPTA-01', '2') });
normal.push({ level: 'Information', time: t(7, 9, 0, 0), source: 'Service Control Manager',
  id: 7045, task: 'Service Installation', user: 'admin.local', computer: 'SRV-FICHIER-02', keywords: 'Classic',
  message: msg7045('ExempleBackupAgent', 'admin.local') });
normal.push({ level: 'Information', time: t(7, 9, 15, 0), source: 'Microsoft-Windows-PowerShell',
  id: 4104, task: 'Execute a Remote Command', user: 'admin.local', computer: 'SRV-FICHIER-02', keywords: 'Classic',
  message: msg4104('Get-Service | Where-Object {$_.Status -eq "Running"}', 'admin.local') });

/* ---------------- 2. Echecs de connexion repetes ---------------- */
const guessing = [];
for (let i = 0; i < 12; i++) {
  guessing.push({ level: 'Error', time: t(8, 2, 10 + i, 5), source: 'Microsoft-Windows-Security-Auditing',
    id: 4625, task: 'Logon', user: 'jsmith', computer: 'PC-DEV-07', keywords: 'Audit Failure',
    message: msg4625('jsmith', '192.168.10.25', 'PC-DEV-07', '3') });
}
guessing.push({ level: 'Information', time: t(8, 2, 24, 40), source: 'Microsoft-Windows-Security-Auditing',
  id: 4624, task: 'Logon', user: 'jsmith', computer: 'PC-DEV-07', keywords: 'Audit Success',
  message: msg4624('jsmith', '192.168.10.25', 'PC-DEV-07', '3') });
guessing.push({ level: 'Information', time: t(8, 2, 26, 0), source: 'Microsoft-Windows-Security-Auditing',
  id: 4688, task: 'Process Creation', user: 'jsmith', computer: 'PC-DEV-07', keywords: 'Audit Success',
  message: msg4688('C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\explorer.exe', 'jsmith') });

/* ---------------- 3. Compte cree puis privileges ---------------- */
const persistence = [
  { level: 'Information', time: t(9, 15, 40, 10), source: 'Microsoft-Windows-Security-Auditing',
    id: 4720, task: 'User Account Management', user: 'admin.local', computer: 'SRV-AD-01',
    keywords: 'Audit Success', message: msg4720('temp-admin', 'admin.local', 'SRV-AD-01') },
  { level: 'Information', time: t(9, 15, 41, 30), source: 'Microsoft-Windows-Security-Auditing',
    id: 4732, task: 'Security Group Management', user: 'admin.local', computer: 'SRV-AD-01',
    keywords: 'Audit Success', message: msg4732('temp-admin', 'Administrators', 'admin.local') },
  { level: 'Information', time: t(9, 15, 50, 0), source: 'Microsoft-Windows-Security-Auditing',
    id: 4624, task: 'Logon', user: 'temp-admin', computer: 'SRV-AD-01', keywords: 'Audit Success',
    message: msg4624('temp-admin', '192.168.10.99', 'SRV-AD-01', '10') },
  { level: 'Information', time: t(9, 16, 5, 0), source: 'Microsoft-Windows-Security-Auditing',
    id: 4688, task: 'Process Creation', user: 'temp-admin', computer: 'SRV-AD-01', keywords: 'Audit Success',
    message: msg4688('C:\\Windows\\System32\\whoami.exe', 'C:\\Windows\\System32\\cmd.exe', 'temp-admin') }
];


/* ---------------- 4. Activite administrative suspecte (mixte) ---------------- */
const mixed = [];
for (let i = 0; i < 7; i++) {
  mixed.push({ level: 'Error', time: t(10, 3, 12 + i, 2), source: 'Microsoft-Windows-Security-Auditing',
    id: 4625, task: 'Logon', user: 'r.dubois', computer: 'PC-DEV-07', keywords: 'Audit Failure',
    message: msg4625('r.dubois', '203.0.113.77', 'PC-DEV-07', '3') });
}
mixed.push({ level: 'Information', time: t(10, 3, 22, 15), source: 'Microsoft-Windows-Security-Auditing',
  id: 4624, task: 'Logon', user: 'r.dubois', computer: 'PC-DEV-07', keywords: 'Audit Success',
  message: msg4624('r.dubois', '203.0.113.77', 'PC-DEV-07', '3') });
mixed.push({ level: 'Information', time: t(10, 3, 25, 0), source: 'Microsoft-Windows-Security-Auditing',
  id: 4720, task: 'User Account Management', user: 'r.dubois', computer: 'SRV-AD-01',
  keywords: 'Audit Success', message: msg4720('support-temp', 'r.dubois', 'SRV-AD-01') });
mixed.push({ level: 'Information', time: t(10, 3, 26, 10), source: 'Microsoft-Windows-Security-Auditing',
  id: 4728, task: 'Security Group Management', user: 'r.dubois', computer: 'SRV-AD-01',
  keywords: 'Audit Success', message: msg4728('support-temp', 'Domain Admins', 'r.dubois') });
mixed.push({ level: 'Information', time: t(10, 3, 30, 0), source: 'Service Control Manager',
  id: 7045, task: 'Service Installation', user: 'r.dubois', computer: 'SRV-AD-01', keywords: 'Classic',
  message: msg7045('WinUpdateHelper', 'r.dubois') });
mixed.push({ level: 'Information', time: t(10, 3, 34, 0), source: 'Microsoft-Windows-PowerShell',
  id: 4104, task: 'Execute a Remote Command', user: 'r.dubois', computer: 'SRV-AD-01', keywords: 'Classic',
  message: msg4104('powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA', 'r.dubois') });
mixed.push({ level: 'Warning', time: t(10, 3, 36, 0), source: 'Microsoft-Windows-Security-Auditing',
  id: 1102, task: 'Audit Log Cleared', user: 'r.dubois', computer: 'SRV-AD-01', keywords: 'Audit Success',
  message: msg1102('r.dubois') });

/* ---------------- Ecriture des fichiers ---------------- */
const files = {
  'normal-windows-events.csv': build(normal),
  'password-guessing.csv': build(guessing),
  'account-persistence.csv': build(persistence),
  'suspicious-admin-activity.csv': build(mixed)
};

if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
for (const name of Object.keys(files)) {
  fs.writeFileSync(path.join(outDir, name), files[name], 'utf8');
  console.log(name + ' ecrit (' + files[name].length + ' octets)');
}

