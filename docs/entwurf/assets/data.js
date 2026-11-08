/* Entwurf: Beispieldaten. ALLES ERFUNDEN – CVE-, WID-, USN- und DSA-Nummern, Versionen und Werte sind fiktiv.
   „Heute“ ist im Entwurf der 2026-11-04, letzte Prüfung 14:48. */
window.D = (function () {
  const NOW = '2026-11-04';

  // Priorität (Vorschlag, offen gelegt auf der Detailseite):
  //   CVSS × 7 (max. 70) + EPSS-Perzentil × 20 (max. 20) + Vertrauen (hoch 10, mittel 5, niedrig 0);
  //   KEV: mindestens 90. Ergebnis 0–100.
  function prio(m) {
    const c = m.cvss * 7;
    const e = m.epssP * 20;
    const v = { hoch: 10, mittel: 5, niedrig: 0 }[m.conf] || 0;
    let p = c + e + v;
    const raw = p;
    if (m.kev) p = Math.max(p, 90);
    return { value: Math.round(p), parts: { cvss: c, epss: e, conf: v, raw: raw, kevFloor: !!m.kev && raw < 90 } };
  }
  function band(p) { return p >= 85 ? 'crit' : p >= 65 ? 'high' : p >= 45 ? 'med' : 'low'; }
  const SEV_LABEL = { crit: 'Kritisch', high: 'Hoch', med: 'Mittel', low: 'Niedrig' };
  function cvssBand(s) { return s >= 9 ? 'crit' : s >= 7 ? 'high' : s >= 4 ? 'med' : 'low'; }

  const hosts = [
    { id: 'server01', name: 'server01', kind: 'host', os: 'Ubuntu 26.04 LTS', via: 'SSH', pkgs: 1243, last: 'vor 2 h 10 min' },
    { id: 'pi01', name: 'pi01', kind: 'host', os: 'Debian 13 (Raspberry Pi OS)', via: 'SSH', pkgs: 812, last: 'vor 2 h 12 min' },
    { id: 'nas01', name: 'nas01', kind: 'host', os: 'Debian 13', via: 'SSH', pkgs: 967, last: 'vor 2 h 11 min' },
    { id: 'app01', name: 'app01', kind: 'host', os: 'Ubuntu 24.04', via: 'von Hand', pkgs: 0 },
    { id: 'router01', name: 'NR-750', kind: 'device', os: 'NordOS 4.2.0', via: 'opennetmon', vendor: 'Nordlicht' },
    { id: 'router02', name: 'Kestrel KG-200', kind: 'device', os: 'Firmware 2.2.6', via: 'opennetmon', vendor: 'Kestrel' },
    { id: 'modem01', name: 'Wellen 5G-Modem M5', kind: 'device', os: 'Firmware 11.0.2', via: 'von Hand', vendor: 'Wellen' }
  ];

  const M = [
    {
      id: 'CVE-2026-41872', cves: ['CVE-2026-41872'], state: 'neu',
      title: 'OpenSSH sshd: Codeausführung vor der Anmeldung durch Race Condition',
      vendor: 'OpenBSD', product: 'OpenSSH', type: 'Software',
      cvss: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', epss: 0.912, epssP: 0.996,
      kev: { since: '2026-10-29', due: '2026-11-19', ransomware: 'unbekannt' }, conf: 'hoch',
      published: '2026-10-27', firstSeen: '2026-10-28 08:12',
      desc: 'Eine Race Condition in der Signalbehandlung von sshd erlaubt einem nicht angemeldeten Angreifer aus dem Netz unter Umständen, Code mit den Rechten von sshd auszuführen. Betroffen sind Versionen vor 10.0p2.',
      assets: [
        { name: 'openssh-server', host: 'server01', installed: '1:10.0p1-5ubuntu1', fixed: '1:10.0p1-5ubuntu1.2', reason: 'Ubuntu-Paketstatus (USN, OSV)' },
        { name: 'openssh-server', host: 'pi01', installed: '1:10.0p1-7', fixed: '1:10.0p1-7+deb13u1', reason: 'Debian-Paketstatus (DSA, OSV)' },
        { name: 'openssh-server', host: 'nas01', installed: '1:10.0p1-7', fixed: '1:10.0p1-7+deb13u1', reason: 'Debian-Paketstatus (DSA, OSV)' }
      ],
      sources: [
        { kind: 'USN', id: 'USN-8123-1', t: 'OpenSSH vulnerability', d: '2026-10-28' },
        { kind: 'DSA', id: 'DSA-6071-1', t: 'openssh – security update', d: '2026-10-28' },
        { kind: 'BSI', id: 'WID-SEC-2026-2241', t: 'OpenSSH: Schwachstelle ermöglicht Codeausführung', d: '2026-10-27' },
        { kind: 'KEV', id: 'CISA KEV', t: 'OpenBSD OpenSSH Race Condition Vulnerability', d: '2026-10-29' },
        { kind: 'CVE', id: 'cvelistV5', t: 'CNA: MITRE', d: '2026-10-27' },
        { kind: 'NVD', id: 'NVD', t: 'CVSS 3.1 und CPE-Konfiguration', d: '2026-10-30' }
      ],
      timeline: [['2026-10-28 08:12', 'Treffer erkannt (USN-8123-1, server01)'], ['2026-10-28 08:13', 'Sofort-Mail gesendet'], ['2026-10-29 20:05', 'In CISA KEV aufgenommen, Priorität 98'], ['2026-10-30 10:41', 'Weitere Hosts: pi01, nas01 (DSA-6071-1)']]
    },
    {
      id: 'CVE-2026-40355', cves: ['CVE-2026-40355'], state: 'neu',
      title: 'Linux-Kernel: Rechteausweitung über io_uring',
      vendor: 'Linux', product: 'Kernel', type: 'Software',
      cvss: 7.8, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', epss: 0.037, epssP: 0.82,
      kev: { since: '2026-10-14', due: '2026-11-04', ransomware: 'bekannt' }, conf: 'hoch',
      published: '2026-10-09', firstSeen: '2026-11-04 08:02',
      desc: 'Ein Use-after-free im io_uring-Teil des Linux-Kernels erlaubt einem lokalen Benutzer, Root-Rechte zu erlangen. Wird laut CISA aktiv ausgenutzt.',
      assets: [
        { name: 'linux-image-7.0.0-41-generic', host: 'server01', installed: '7.0.0-41.42', fixed: '7.0.0-42.43', reason: 'Ubuntu-Paketstatus (USN, OSV)', note: 'Neuer Kernel installiert, Neustart steht aus' }
      ],
      sources: [
        { kind: 'USN', id: 'USN-8140-1', t: 'Linux kernel vulnerabilities', d: '2026-11-03' },
        { kind: 'KEV', id: 'CISA KEV', t: 'Linux Kernel Use-After-Free Vulnerability', d: '2026-10-14' },
        { kind: 'CVE', id: 'cvelistV5', t: 'CNA: Linux', d: '2026-10-09' }
      ],
      timeline: [['2026-11-04 08:02', 'Treffer erkannt (USN-8140-1)'], ['2026-11-04 08:02', 'Sofort-Mail gesendet (KEV)']]
    },
    {
      id: 'CVE-2026-39011', cves: ['CVE-2026-39011'], state: 'neu',
      title: 'NordOS: Umgehung der Anmeldung in der Weboberfläche',
      vendor: 'Nordlicht', product: 'NR-750', type: 'Hardware',
      cvss: 8.8, vector: 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', epss: 0.214, epssP: 0.951,
      kev: null, conf: 'mittel',
      published: '2026-11-03', firstSeen: '2026-11-03 18:40',
      desc: 'Ein Angreifer im lokalen Netz kann die Anmeldung an der Weboberfläche umgehen und die Konfiguration ändern. Nordlicht stellt NordOS 4.2.1 bereit.',
      assets: [
        { name: 'NR-750', host: 'NR-750', installed: 'NordOS 4.2.0', fixed: 'NordOS 4.2.1', reason: 'CSAF-Produktbaum: Hersteller und Produkt, Version aus opennetmon (sysDescr)' }
      ],
      sources: [
        { kind: 'BSI', id: 'WID-SEC-2026-2198', t: 'Nordlicht NordOS: Schwachstelle ermöglicht Umgehen von Sicherheitsvorkehrungen', d: '2026-11-03' },
        { kind: 'CVE', id: 'cvelistV5', t: 'CNA: CERT@VDE', d: '2026-11-03' }
      ],
      timeline: [['2026-11-03 18:40', 'Treffer erkannt (BSI CERT-Bund)'], ['2026-11-03 18:40', 'Sofort-Mail gesendet']]
    },
    {
      id: 'CVE-2026-38877', cves: ['CVE-2026-38877', 'CVE-2026-38878'], state: 'neu',
      title: 'Kestrel KG-200: Befehlseinschleusung in der Weboberfläche',
      vendor: 'Kestrel', product: 'KG-200', type: 'Hardware',
      cvss: 8.0, vector: 'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', epss: 0.31, epssP: 0.97,
      kev: null, conf: 'mittel',
      published: '2026-10-31', firstSeen: '2026-11-01 06:20',
      desc: 'Ein angemeldeter Benutzer im lokalen Netz kann über ein Diagnosefeld Betriebssystembefehle einschleusen. Behoben in Firmware 2.3.0.',
      assets: [
        { name: 'Kestrel KG-200', host: 'Kestrel KG-200', installed: '2.2.6', fixed: '2.3.0', reason: 'CSAF-Produktbaum (BSI), Version aus opennetmon' }
      ],
      sources: [
        { kind: 'BSI', id: 'WID-SEC-2026-2170', t: 'Kestrel Router: Mehrere Schwachstellen', d: '2026-10-31' },
        { kind: 'CVE', id: 'cvelistV5', t: 'CNA: Kestrel', d: '2026-10-31' }
      ],
      timeline: [['2026-11-01 06:20', 'Treffer erkannt (BSI CERT-Bund)'], ['2026-11-01 06:20', 'Sofort-Mail gesendet']]
    },
    {
      id: 'CVE-2026-37720', cves: ['CVE-2026-37720'], state: 'gesehen',
      title: 'curl: Heap-Überlauf beim SOCKS5-Handshake',
      vendor: 'curl', product: 'curl / libcurl', type: 'Software',
      cvss: 7.3, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H', epss: 0.009, epssP: 0.55,
      kev: null, conf: 'hoch',
      published: '2026-10-22', firstSeen: '2026-10-23 08:05',
      desc: 'Bei sehr langen Hostnamen über einen SOCKS5-Proxy kann curl einen Heap-Puffer überschreiben.',
      assets: [
        { name: 'libcurl4t64', host: 'server01', installed: '8.16.0-2ubuntu1', fixed: '8.16.0-2ubuntu1.1', reason: 'Ubuntu-Paketstatus' },
        { name: 'libcurl4t64', host: 'pi01', installed: '8.14.1-2', fixed: '8.14.1-2+deb13u2', reason: 'Debian-Paketstatus' },
        { name: 'libcurl4t64', host: 'nas01', installed: '8.14.1-2', fixed: '8.14.1-2+deb13u2', reason: 'Debian-Paketstatus' }
      ],
      sources: [
        { kind: 'USN', id: 'USN-8102-1', t: 'curl vulnerability', d: '2026-10-23' },
        { kind: 'DSA', id: 'DSA-6060-1', t: 'curl – security update', d: '2026-10-23' },
        { kind: 'CVE', id: 'cvelistV5', t: 'CNA: curl', d: '2026-10-22' }
      ],
      timeline: [['2026-10-23 08:05', 'Treffer erkannt'], ['2026-10-23 19:31', 'Gesehen']]
    },
    {
      id: 'CVE-2026-42210', cves: ['CVE-2026-42210'], state: 'neu',
      title: 'glibc: Pufferüberlauf in iconv()',
      vendor: 'GNU', product: 'glibc', type: 'Software',
      cvss: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', epss: 0.012, epssP: 0.40,
      kev: null, conf: 'hoch',
      published: '2026-11-02', firstSeen: '2026-11-04 14:48',
      desc: 'Beim Umwandeln bestimmter Zeichensätze kann iconv() über das Pufferende schreiben. Programme, die fremde Eingaben umwandeln, können abstürzen.',
      assets: [
        { name: 'libc6', host: 'server01', installed: '2.42-0ubuntu3', fixed: '2.42-0ubuntu3.1', reason: 'Ubuntu-Paketstatus' },
        { name: 'libc6', host: 'pi01', installed: '2.41-12', fixed: '2.41-12+deb13u1', reason: 'Debian-Paketstatus' },
        { name: 'libc6', host: 'nas01', installed: '2.41-12', fixed: '2.41-12+deb13u1', reason: 'Debian-Paketstatus' }
      ],
      sources: [
        { kind: 'USN', id: 'USN-8144-1', t: 'GNU C Library vulnerability', d: '2026-11-04' },
        { kind: 'DSA', id: 'DSA-6080-1', t: 'glibc – security update', d: '2026-11-04' },
        { kind: 'CVE', id: 'cvelistV5', t: 'CNA: GNU', d: '2026-11-02' }
      ],
      timeline: [['2026-11-04 14:48', 'Treffer erkannt']]
    },
    {
      id: 'CVE-2026-33410', cves: ['CVE-2026-33410'], state: 'spaeter', until: '2026-11-11',
      title: 'Fieldnet Controller: Sitzungstokens im Protokoll',
      vendor: 'Kestrel', product: 'Fieldnet Controller', type: 'Software',
      cvss: 6.8, vector: 'CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', epss: 0.006, epssP: 0.45,
      kev: null, conf: 'mittel',
      published: '2026-10-18', firstSeen: '2026-10-19 08:00',
      desc: 'Der Controller schreibt Sitzungstokens in eine Protokolldatei, die für angemeldete Benutzer lesbar ist.',
      assets: [{ name: 'Fieldnet Controller', host: 'server01', installed: '6.2.0', fixed: '6.3.0', reason: 'CSAF-Produktbaum, Version von Hand' }],
      sources: [{ kind: 'BSI', id: 'WID-SEC-2026-2088', t: 'Kestrel Fieldnet: Schwachstelle ermöglicht Offenlegung von Informationen', d: '2026-10-18' }],
      timeline: [['2026-10-19 08:00', 'Treffer erkannt'], ['2026-10-20 21:14', 'Später: bis 2026-11-11 („Update mit Fieldnet 6.3“)']]
    },
    {
      id: 'CVE-2026-41003', cves: ['CVE-2026-41003'], state: 'gesehen',
      title: 'Traefik: Umgehung von Pfadregeln durch kodierte Zeichen',
      vendor: 'Traefik Labs', product: 'Traefik', type: 'Software',
      cvss: 6.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', epss: 0.004, epssP: 0.30,
      kev: null, conf: 'hoch',
      published: '2026-10-30', firstSeen: '2026-10-30 12:02',
      desc: 'Prozentkodierte Schrägstriche werden nach der Routenprüfung dekodiert. Dadurch greifen Pfadregeln nicht immer.',
      assets: [{ name: 'Traefik', host: 'server01', installed: '3.7.1', fixed: '3.7.3', reason: 'CPE mit Versionsbereich (cvelistV5)' }],
      sources: [{ kind: 'CVE', id: 'cvelistV5', t: 'CNA: GitHub (GHSA)', d: '2026-10-30' }, { kind: 'NVD', id: 'NVD', t: 'noch nicht angereichert', d: '–' }],
      timeline: [['2026-10-30 12:02', 'Treffer erkannt'], ['2026-10-30 12:30', 'Gesehen']]
    },
    {
      id: 'WID-SEC-2026-2304', cves: ['CVE-2026-40071', 'CVE-2026-40072', 'CVE-2026-40079'], state: 'neu',
      title: 'Wellen 5G-Modem: Mehrere Schwachstellen',
      vendor: 'Wellen', product: '5G-Modem M5', type: 'Hardware',
      cvss: 7.1, vector: 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H', epss: 0.02, epssP: 0.50,
      kev: null, conf: 'niedrig',
      published: '2026-11-02', firstSeen: '2026-11-02 14:30',
      desc: 'Wellen meldet mehrere Schwachstellen in Firmware für 5G-Router. Welche Modelle betroffen sind, ist im Advisory nur allgemein angegeben.',
      assets: [{ name: 'Wellen 5G-Modem M5', host: 'Wellen 5G-Modem M5', installed: '11.0.2', fixed: 'unbekannt', reason: 'Stichwort „Wellen 5G-Modem“ aus der Watchlist' }],
      sources: [{ kind: 'BSI', id: 'WID-SEC-2026-2304', t: 'Wellen Router: Mehrere Schwachstellen', d: '2026-11-02' }],
      timeline: [['2026-11-02 14:30', 'Treffer erkannt (Stichwort)']]
    },
    {
      id: 'CVE-2026-36512', cves: ['CVE-2026-36512'], state: 'gesehen',
      title: 'Hausautomat Core: Gespeichertes XSS in Kartenkonfiguration',
      vendor: 'Hausautomat', product: 'Hausautomat Core', type: 'Software',
      cvss: 5.4, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', epss: 0.003, epssP: 0.20,
      kev: null, conf: 'hoch',
      published: '2026-10-25', firstSeen: '2026-10-25 20:10',
      desc: 'Ein Benutzer mit Bearbeitungsrechten kann Skript in eine Dashboard-Karte einfügen, das bei anderen Benutzern ausgeführt wird.',
      assets: [{ name: 'Hausautomat Core', host: 'app01', installed: '2026.10.2', fixed: '2026.10.4', reason: 'CPE mit Versionsbereich' }],
      sources: [{ kind: 'CVE', id: 'cvelistV5', t: 'CNA: GitHub (GHSA)', d: '2026-10-25' }],
      timeline: [['2026-10-25 20:10', 'Treffer erkannt'], ['2026-10-26 07:55', 'Gesehen']]
    },
    {
      id: 'CVE-2026-35190', cves: ['CVE-2026-35190'], state: 'gesehen',
      title: 'OpenSSL: Dienstblockade bei der Prüfung von X.509-Namen',
      vendor: 'OpenSSL', product: 'OpenSSL', type: 'Software',
      cvss: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', epss: 0.002, epssP: 0.10,
      kev: null, conf: 'hoch',
      published: '2026-10-14', firstSeen: '2026-10-15 08:00',
      desc: 'Ein präpariertes Zertifikat kann bei der Namensprüfung viel Rechenzeit verbrauchen.',
      assets: [{ name: 'libssl3t64', host: 'server01', installed: '3.5.3-1ubuntu2', fixed: '3.5.3-1ubuntu2.1', reason: 'Ubuntu-Paketstatus' }],
      sources: [{ kind: 'USN', id: 'USN-8090-1', t: 'OpenSSL vulnerability', d: '2026-10-15' }],
      timeline: [['2026-10-15 08:00', 'Treffer erkannt'], ['2026-10-15 18:12', 'Gesehen']]
    },
    {
      id: 'CVE-2026-39960', cves: ['CVE-2026-39960'], state: 'gesehen',
      title: 'Samba: Preisgabe von Informationen über DCE/RPC',
      vendor: 'Samba', product: 'Samba', type: 'Software',
      cvss: 4.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', epss: 0.002, epssP: 0.10,
      kev: null, conf: 'hoch',
      published: '2026-10-28', firstSeen: '2026-10-29 08:00',
      desc: 'Ein angemeldeter Benutzer kann über DCE/RPC Namen von Freigaben abfragen, die ihm nicht angezeigt werden sollen.',
      assets: [{ name: 'samba', host: 'nas01', installed: '2:4.22.4+dfsg-1', fixed: '2:4.22.4+dfsg-1+deb13u1', reason: 'Debian-Paketstatus' }],
      sources: [{ kind: 'DSA', id: 'DSA-6066-1', t: 'samba – security update', d: '2026-10-29' }],
      timeline: [['2026-10-29 08:00', 'Treffer erkannt'], ['2026-10-29 21:40', 'Gesehen']]
    },
    {
      id: 'CVE-2026-31877', cves: ['CVE-2026-31877'], state: 'gesehen',
      title: 'Speicherpanel: CSRF in der Weboberfläche',
      vendor: 'Speicherpanel', product: 'speicherpanel', type: 'Software',
      cvss: 4.6, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N', epss: 0.003, epssP: 0.15,
      kev: null, conf: 'mittel',
      published: '2026-10-20', firstSeen: '2026-10-21 08:00',
      desc: 'Fehlende CSRF-Prüfung bei einigen Einstellungsseiten.',
      assets: [{ name: 'speicherpanel', host: 'nas01', installed: '8.6.1-1', fixed: '8.6.3-1', reason: 'Stichwort und Paketname, Version aus dpkg' }],
      sources: [{ kind: 'CVE', id: 'cvelistV5', t: 'CNA: VulDB', d: '2026-10-20' }],
      timeline: [['2026-10-21 08:00', 'Treffer erkannt'], ['2026-10-21 12:00', 'Gesehen']]
    },
    {
      id: 'CVE-2026-30115', cves: ['CVE-2026-30115'], state: 'erledigt',
      title: 'sudo: Rechteausweitung über die Option --chroot',
      vendor: 'sudo', product: 'sudo', type: 'Software',
      cvss: 7.0, vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H', epss: 0.02, epssP: 0.60,
      kev: null, conf: 'hoch',
      published: '2026-10-10', firstSeen: '2026-10-11 08:00',
      desc: 'Ein lokaler Benutzer kann über eine präparierte chroot-Umgebung Root-Rechte erlangen.',
      assets: [{ name: 'sudo', host: 'server01', installed: '1.9.17p2-1ubuntu1.1', fixed: '1.9.17p2-1ubuntu1.1', reason: 'Ubuntu-Paketstatus' }],
      sources: [{ kind: 'USN', id: 'USN-8071-1', t: 'sudo vulnerability', d: '2026-10-11' }],
      timeline: [['2026-10-11 08:00', 'Treffer erkannt'], ['2026-10-12 06:30', 'Automatisch erledigt: behobene Version installiert (SSH-Abfrage)']]
    },
    {
      id: 'CVE-2026-29001', cves: ['CVE-2026-29001'], state: 'ignoriert', reason: 'Funktion nicht genutzt',
      title: 'Raspberry Pi Firmware: Umgehung von Secure Boot',
      vendor: 'Raspberry Pi', product: 'Firmware', type: 'Software',
      cvss: 5.9, vector: 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', epss: 0.001, epssP: 0.12,
      kev: null, conf: 'mittel',
      published: '2026-09-30', firstSeen: '2026-10-01 08:00',
      desc: 'Mit physischem Zugriff lässt sich die Signaturprüfung beim Start umgehen.',
      assets: [{ name: 'raspi-firmware', host: 'pi01', installed: '1:1.20250915-1', fixed: '1:1.20251020-1', reason: 'Debian-Paketstatus' }],
      sources: [{ kind: 'DSA', id: 'DSA-6034-1', t: 'raspi-firmware – security update', d: '2026-10-01' }],
      timeline: [['2026-10-01 08:00', 'Treffer erkannt'], ['2026-10-02 19:00', 'Ignoriert: „Funktion nicht genutzt“ (nur pi01)']]
    }
  ];

  M.forEach(function (m) {
    const p = prio(m);
    m.prio = p.value; m.prioParts = p.parts; m.sev = band(p.value);
    m.hosts = Array.from(new Set(m.assets.map(function (a) { return a.host; })));
    m.srcKinds = Array.from(new Set(m.sources.map(function (s) { return s.kind; })));
  });
  M.sort(function (a, b) { return b.prio - a.prio; });

  // Weitere CVEs ohne eigene Treffer (für „Alle CVEs“)
  const extra = [
    ['CVE-2026-42377', 'Microsoft Exchange Server: Codeausführung über präparierte Mail', 'Microsoft', 9.1, 0.42, 0.98, true, '2026-11-04'],
    ['CVE-2026-42301', 'Fortinet FortiOS: Pufferüberlauf im SSL-VPN', 'Fortinet', 9.6, 0.71, 0.99, true, '2026-11-03'],
    ['CVE-2026-42288', 'Apache HTTP Server: Request Smuggling in mod_proxy', 'Apache', 7.5, 0.05, 0.88, false, '2026-11-03'],
    ['CVE-2026-42190', 'Cisco IOS XE: Rechteausweitung über die Weboberfläche', 'Cisco', 8.8, 0.12, 0.94, false, '2026-11-02'],
    ['CVE-2026-42155', 'Siemens SIMATIC S7-1500: Dienstblockade über präparierte Pakete', 'Siemens', 7.5, 0.004, 0.31, false, '2026-11-02'],
    ['CVE-2026-42102', 'Synology DSM: Pfad-Traversierung im Dateidienst', 'Synology', 6.5, 0.008, 0.52, false, '2026-11-01'],
    ['CVE-2026-42050', 'Red Hat Keycloak: Offene Weiterleitung nach der Anmeldung', 'Red Hat', 5.4, 0.003, 0.19, false, '2026-11-01'],
    ['CVE-2026-41988', 'SUSE Rancher: Preisgabe von Zugangsdaten im Audit-Log', 'SUSE', 6.5, 0.002, 0.12, false, '2026-10-31'],
    ['CVE-2026-41950', 'Nextcloud Server: Umgehung der Freigabe-Passwörter', 'Nextcloud', 5.3, 0.006, 0.44, false, '2026-10-31'],
    ['CVE-2026-41912', 'Google Chrome: Type Confusion in V8', 'Google', 8.8, 0.33, 0.97, true, '2026-10-30'],
    ['CVE-2026-41877', 'Mozilla Firefox: Use-after-free im DOM', 'Mozilla', 8.1, 0.02, 0.71, false, '2026-10-30'],
    ['CVE-2026-41840', 'PHP: Pufferüberlauf in mb_convert_encoding()', 'PHP', 7.3, 0.01, 0.58, false, '2026-10-29'],
    ['CVE-2026-41799', 'Docker Engine: Ausbruch aus dem Container über Bind-Mounts', 'Docker', 8.6, 0.04, 0.86, false, '2026-10-29'],
    ['CVE-2026-41760', 'Grafana: Gespeichertes XSS in Annotationen', 'Grafana Labs', 5.4, 0.003, 0.22, false, '2026-10-28'],
    ['CVE-2026-41721', 'WordPress: Rechteausweitung über die REST-API', 'WordPress', 6.3, 0.02, 0.66, false, '2026-10-28'],
    ['CVE-2026-41690', 'Wellen MobileOS: Preisgabe von Informationen', 'Wellen', 4.4, 0.001, 0.05, false, '2026-10-27'],
    ['CVE-2026-41655', 'Ivanti Connect Secure: Authentifizierungsumgehung', 'Ivanti', 9.8, 0.88, 0.995, true, '2026-10-27'],
    ['CVE-2026-41601', 'Zyxel NAS: Befehlseinschleusung über CGI', 'Zyxel', 9.8, 0.6, 0.99, false, '2026-10-26'],
    ['CVE-2026-41577', 'Python: ReDoS im Modul email', 'Python', 5.3, 0.002, 0.14, false, '2026-10-26'],
    ['CVE-2026-41540', 'Node.js: HTTP-Header-Injection', 'Node.js', 6.1, 0.004, 0.33, false, '2026-10-25']
  ].map(function (r) {
    const m = { id: r[0], cves: [r[0]], title: r[1], vendor: r[2], product: r[2], cvss: r[3], epss: r[4], epssP: r[5], kev: r[6] ? { since: r[7], due: '2026-11-25', ransomware: 'unbekannt' } : null, conf: null, published: r[7], assets: [], sources: [{ kind: 'CVE', id: 'cvelistV5', t: 'CNA-Angaben', d: r[7] }, { kind: 'NVD', id: 'NVD', t: 'CVSS 3.1', d: r[7] }], vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', desc: 'Beispieleintrag ohne Treffer bei den eigenen Assets.', timeline: [] };
    if (r[6]) m.sources.push({ kind: 'KEV', id: 'CISA KEV', t: 'Known Exploited Vulnerability', d: r[7] });
    const p = prio(m); m.prio = p.value; m.prioParts = p.parts; m.sev = band(p.value);
    m.hosts = []; m.srcKinds = m.sources.map(function (s) { return s.kind; });
    return m;
  });

  const all = M.concat(extra).sort(function (a, b) { return a.published < b.published ? 1 : a.published > b.published ? -1 : b.prio - a.prio; });

  const sources = [
    { id: 'cvelist', name: 'CVE-Liste (cvelistV5)', state: 'ok', last: '14:05', dur: '18 s', nw: 12, ch: 41, next: '15:05', iv: '1 h', on: true, lic: 'CVE Terms of Use. Quelle: CVE Program (MITRE).', detail: 'Stündliches Delta 2026-11-04_1400Z, 53 Datensätze.' },
    { id: 'nvd', name: 'NVD (Anreicherung)', state: 'ok', last: '14:40', dur: '6 s', nw: 0, ch: 88, next: '16:40', iv: '2 h', on: true, lic: 'This product uses data from the NVD but is not endorsed or certified by the NVD.', detail: 'Feed nvdcve-2.0-modified, SHA-256 geprüft. Hinweis: NIST reichert seit 15.04.2026 nur noch priorisierte CVEs an.' },
    { id: 'kev', name: 'CISA KEV', state: 'ok', last: '12:00', dur: '1 s', nw: 1, ch: 0, next: '18:00', iv: '6 h', on: true, lic: 'CC0 1.0. Quelle: CISA.', detail: 'Bedingter Abruf, 1 neuer Eintrag.' },
    { id: 'epss', name: 'FIRST EPSS', state: 'ok', last: '08:10', dur: '4 s', nw: 0, ch: 294113, next: 'morgen 08:10', iv: 'täglich', on: true, lic: 'EPSS von FIRST.org, Quellenangabe erbeten.', detail: 'Tabelle mit 294 113 Werten ersetzt (Modell v2025.03.14).' },
    { id: 'bsi', name: 'BSI CERT-Bund (CSAF, TLP:WHITE)', state: 'ok', last: '14:30', dur: '9 s', nw: 3, ch: 7, next: '16:30', iv: '2 h', on: true, lic: 'Bundesamt für Sicherheit in der Informationstechnik, CERT-Bund. Nutzungsbedingungen [noch prüfen].', detail: 'ROLIE-Feeds bsi-wid-white, bsi-white, bsi-cvd-white. 10 Dokumente geholt, SHA-256 geprüft.' },
    { id: 'vendor', name: 'Hersteller-CSAF (5 Anbieter)', state: 'warn', last: '12:15', dur: '1 min 52 s', nw: 6, ch: 19, next: '18:15', iv: '6 h', on: true, lic: 'Je Hersteller unterschiedlich, siehe Anbieterliste.', detail: 'Cisco, Red Hat (gefiltert), SUSE, Siemens, Wellen. 1 Dokument von Wellen mit falscher Prüfsumme übersprungen.' },
    { id: 'osv-deb', name: 'Debian (OSV)', state: 'ok', last: '12:20', dur: '11 s', nw: 4, ch: 23, next: '18:20', iv: '6 h', on: true, lic: 'OSV-Daten, Lizenz je Datensatz (Debian).', detail: 'modified_id.csv, 27 Datensätze.' },
    { id: 'tracker', name: 'Debian Security Tracker', state: 'err', last: '12:21', dur: '30 s', nw: 0, ch: 0, next: '14:51 (Wiederholung)', iv: '6 h', on: true, lic: 'Debian Security Team [Lizenz noch prüfen].', detail: 'HTTP 503 Service Unavailable. 3. Versuch, nächster in 30 min (Backoff).' },
    { id: 'osv-ubu', name: 'Ubuntu (OSV)', state: 'ok', last: '12:22', dur: '9 s', nw: 3, ch: 15, next: '18:22', iv: '6 h', on: true, lic: 'OSV-Daten, Lizenz je Datensatz (Ubuntu).', detail: 'modified_id.csv, 18 Datensätze.' },
    { id: 'usn', name: 'Ubuntu Security Notices', state: 'ok', last: '12:23', dur: '3 s', nw: 2, ch: 0, next: '18:23', iv: '6 h', on: true, lic: 'CC BY-SA 4.0, Canonical Ltd.', detail: '2 neue USN-Titel.' },
    { id: 'msrc', name: 'Microsoft (CSAF)', state: 'off', last: '–', dur: '–', nw: 0, ch: 0, next: '–', iv: '6 h', on: false, lic: 'Microsoft Security Response Center.', detail: 'Ausgeschaltet: keine Microsoft-Assets.' }
  ];

  const audit = [
    ['2026-11-04 14:52', 'admin', 'Treffer CVE-2026-37720 als gesehen markiert'],
    ['2026-11-04 09:10', 'admin', 'Asset „Traefik 3.7.1“ von Hand angelegt'],
    ['2026-11-03 21:03', 'admin', 'Host nas01: Host-Schlüssel bestätigt (ED25519 SHA256:q3v…Xw)'],
    ['2026-11-03 20:58', 'admin', 'Schwelle Sofort-Mail: CVSS ≥ 7,0 → 8,0'],
    ['2026-11-02 19:00', 'admin', 'Quelle „Microsoft (CSAF)“ ausgeschaltet'],
    ['2026-11-02 18:45', 'admin', 'Anmeldung erfolgreich']
  ];

  // 30 Tage offene Treffer je Schwere (für „Lage“)
  const trend = [];
  for (let i = 0; i < 30; i++) {
    const d = new Date(Date.UTC(2026, 9, 6 + i));
    const t = i / 29;
    trend.push({
      d: d.toISOString().slice(0, 10),
      crit: i < 21 ? (i % 9 === 3 ? 1 : 0) : (i < 25 ? 1 : i < 28 ? 2 : 3),
      high: Math.round(2 + 2 * Math.sin(i / 4) + t * 2),
      med: Math.round(4 + 2 * Math.cos(i / 5) + t * 2),
      low: Math.round(3 + Math.sin(i / 3))
    });
  }

  return { NOW: NOW, matches: M, all: all, hosts: hosts, sources: sources, audit: audit, trend: trend, prio: prio, band: band, SEV_LABEL: SEV_LABEL, cvssBand: cvssBand };
})();
