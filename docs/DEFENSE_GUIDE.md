# Defense Guide — Sistema di Difesa Ibrido NIDS + HIDS

Il sistema di difesa implementa una catena a tre livelli: **rilevamento di rete** (Suricata), **correlazione e alerting** (Wazuh), **risposta automatica** (iptables via Active Response).

---

## Architettura difensiva

```
Traffico di rete
      |
      v
[defense — eth0/eth1]
      |
      +---> Suricata (NIDS)
      |       analisi in-line del traffico
      |       scrivi alert in /var/log/suricata/eve.json
      |
      v
[volume condiviso: suricata_logs]
      |
      v
[wazuh-manager]
      |
      +---> logcollector legge eve.json
      +---> analisi regole (local_rules.xml)
      +---> alert level >= 10 → Active Response
      |
      v
[defense — wazuh-execd]
      |
      +---> custom-firewall-drop
      +---> iptables DROP per IP attaccante
```

---

## Suricata NIDS

### Posizione dei file

| File | Percorso nel container |
|---|---|
| Configurazione principale | `/etc/suricata/suricata.yaml` |
| Regole custom | `/etc/suricata/rules/local.rules` |
| Log alert (JSON) | `/var/log/suricata/eve.json` |
| Log alert (testo) | `/var/log/suricata/fast.log` |

### Interfacce monitorate

Suricata ascolta su entrambe le interfacce del nodo `defense`:
- `eth0` — lato rete attaccante (10.0.1.0/24)
- `eth1` — lato rete vittima (10.0.2.0/24)

Tutto il traffico tra le due subnet transita per `defense` grazie all'IP forwarding abilitato (`net.ipv4.ip_forward=1`), rendendo il nodo un punto di ispezione completo.

### Regole custom — CVE-2011-2523

File: `defense/suricata/rules/local.rules`

**SID 9000001 — Trigger backdoor vsftpd**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (
  msg:"EXPLOIT vsftpd 2.3.4 Backdoor Trigger - smiley in FTP USER";
  flow:to_server,established;
  content:"USER ";
  nocase;
  content:":)";
  within:50;
  sid:9000001;
  rev:1;
)
```

Rileva il tentativo di attivazione della backdoor: cerca la stringa `:)` entro 50 byte dalla keyword `USER` nel traffico FTP verso la porta 21. Ogni login FTP che contiene questa sequenza è il trigger della CVE.

**SID 9000002 — Connessione alla shell backdoor**

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 6200 (
  msg:"EXPLOIT vsftpd 2.3.4 Backdoor Shell Connection on port 6200";
  flow:to_server;
  flags:S;
  sid:9000002;
  rev:1;
)
```

Rileva qualsiasi tentativo di connessione TCP verso la porta 6200 della vittima. La porta 6200 è utilizzata esclusivamente dalla backdoor vsftpd — qualsiasi SYN verso di essa indica un attacco in corso o un probe.

### Verifica stato Suricata

```bash
docker exec defense bash -c "ls /var/log/suricata/ && tail -5 /var/log/suricata/fast.log"
```

---

## Wazuh HIDS

### Componenti

| Componente | Container | Ruolo |
|---|---|---|
| Wazuh Manager | `wazuh-manager` | Riceve log, applica regole, invia comandi AR |
| Wazuh Agent (defense) | `defense` | Monitora il nodo defense, esegue Active Response |
| Wazuh Agent (victim) | `victim-agent` | Sidecar su Metasploitable2, File Integrity Monitoring |
| Wazuh Indexer | `wazuh-indexer` | OpenSearch — archivia e indicizza tutti gli alert |
| Wazuh Dashboard | `wazuh-dashboard` | UI web — visualizzazione alert e grafici |

### Integrazione Suricata → Wazuh

Il Wazuh Manager legge `eve.json` direttamente tramite un volume condiviso (`suricata_logs`), configurato in `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
  <label key="@source">suricata</label>
</localfile>
```

Il campo `@source: suricata` permette di filtrare gli alert Suricata nella dashboard.

### Regole custom Wazuh

File: `wazuh/rules/local_rules.xml`

Le regole sono figlie di **86600** (regola base Wazuh per alert Suricata di tipo `event_type=alert`).

**Regola 100001 — livello 12**

```xml
<rule id="100001" level="12">
  <if_sid>86600</if_sid>
  <match>vsftpd 2.3.4 Backdoor</match>
  <description>EXPLOIT vsftpd 2.3.4 Backdoor Trigger - blocco automatico attivato</description>
  <group>attack,exploit,</group>
  <mitre><id>T1190</id></mitre>
</rule>
```

Corrisponde al SID 9000001 di Suricata. Il livello 12 supera la soglia di 10 configurata per l'Active Response, attivando il blocco automatico.

**Regola 100002 — livello 15**

```xml
<rule id="100002" level="15">
  <if_sid>86600</if_sid>
  <match>Backdoor Shell Connection on port 6200</match>
  <description>EXPLOIT vsftpd 2.3.4 Backdoor Shell attiva su porta 6200 - blocco immediato</description>
  <group>attack,exploit,</group>
  <mitre><id>T1059</id></mitre>
</rule>
```

Corrisponde al SID 9000002. Livello 15 — massima priorità. Nella sequenza temporale, questa regola scatta prima di 100001 perché Metasploit effettua probe sulla porta 6200 prima di inviare il trigger FTP.

> **Nota sull'ordine:** SID 9000002 (probe porta 6200) scatta a t+0s, SID 9000001 (trigger FTP) a t+7s. L'Active Response viene attivata da 100001 a t+7s, quando Wazuh ha piena visibilità dell'attacco.

### Verifica alert Wazuh

```bash
docker exec wazuh-manager bash -c "grep -E 'Rule: 100001|Rule: 100002' /var/ossec/logs/alerts/alerts.log"
```

---

## Active Response

### Flusso di attivazione

1. Wazuh Manager riceve alert di livello ≥ 10
2. Invia comando di Active Response all'agente `defense-nids` (ID 001)
3. L'agente esegue `custom-firewall-drop` con l'IP sorgente come argomento
4. Lo script aggiunge una regola `iptables DROP` per quell'IP

### Script custom-firewall-drop

File: `defense/custom-firewall-drop`

Lo script è necessario perché il binario standard `firewall-drop` di Wazuh cerca il campo `srcip` nel JSON dell'alert, mentre Suricata usa `src_ip` (con underscore). Lo script risolve il mismatch estraendo il campo corretto via Python:

```bash
SRC_IP=$(echo "$ALERT_DATA" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('src_ip', data.get('srcip', '')))
")

iptables -I INPUT -s "$SRC_IP" -j DROP
iptables -I FORWARD -s "$SRC_IP" -j DROP
```

Agisce su entrambe le chain:
- `INPUT` — blocca pacchetti destinati al nodo `defense` stesso
- `FORWARD` — blocca i pacchetti che `defense` dovrebbe instradare verso la vittima

### Configurazione in ossec.conf

```xml
<command>
  <name>custom-firewall-drop</name>
  <executable>custom-firewall-drop</executable>
  <expect>src_ip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>custom-firewall-drop</command>
  <location>defined-agent</location>
  <agent_id>001</agent_id>
  <level>10</level>
  <timeout>600</timeout>
</active-response>
```

Il blocco viene rimosso automaticamente dopo **600 secondi** (10 minuti).

### Verifica blocco

```powershell
# Regole iptables applicate
docker exec defense bash -c "iptables -L INPUT -n --line-numbers | grep 10.0.1.10"
docker exec defense bash -c "iptables -L FORWARD -n --line-numbers | grep 10.0.1.10"

# Log Active Response
docker exec defense bash -c "tail -20 /var/ossec/logs/active-responses.log"

# Isolamento attaccante verificato
docker exec attacker ping -c 4 10.0.2.10
```

---

## Wazuh Dashboard

Accessibile su `https://localhost:5601` — credenziali `admin / admin`.

### Sezioni rilevanti

| Sezione | Cosa mostra |
|---|---|
| **Security Events** | Timeline di tutti gli alert, filtrabili per regola e agente |
| **MITRE ATT&CK** | Mapping automatico degli alert alle tecniche MITRE (T1190, T1059) |
| **Integrity Monitoring** | Variazioni file monitorate dal sidecar su Metasploitable2 |
| **Threat Hunting** | Ricerca libera su tutti gli eventi indicizzati |

Per visualizzare solo gli alert dell'attacco CVE-2011-2523, filtrare per `rule.id: 100001 OR rule.id: 100002` nella sezione Security Events.
