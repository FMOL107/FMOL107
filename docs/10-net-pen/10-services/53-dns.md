---
id: dns
title: DNS - 53
---

# DNS - 53

El servicio DNS resuelve nombres de dominio a direcciones IP. Es uno de los primeros servicios a enumerar porque puede revelar subdominios, servidores internos y la estructura de la red.

## Local Host Resolution Override

Permite forzar la resolución de un dominio a una IP concreta en nuestra máquina. Útil cuando no hay DNS accesible o queremos apuntar a un host específico.

```bash
nano /etc/hosts
<IP> <dominio>
```

## Direct Record Query

Consultas directas contra un servidor DNS para obtener distintos tipos de registros.

### Direct A/AAAA Record Query

Obtiene la IP asociada a un dominio (registro A para IPv4, AAAA para IPv6).

```bash
dig @<IP> dominio.dominio
```

### Mail Exchange Records Enumeration (MX)

Identifica los servidores de correo del dominio. Puede revelar infraestructura interna.

```bash
dig @<IP> dominio.dominio mx
```

### Authoritative Name Servers Enumeration (NS)

Enumera los servidores DNS autoritativos. Útil para identificar otros servidores que podrían permitir transferencias de zona.

```bash
dig @<IP> dominio.dominio ns
```

### Full DNS Records Enumeration (ANY)

Solicita todos los registros disponibles de un dominio en una sola consulta.

> Algunos servidores modernos bloquean consultas ANY por motivos de rendimiento y seguridad.

```bash
dig @<IP> dominio.dominio any
```

## Domain Zone Transfer Attack (AXFR)

Intenta obtener una copia completa de la zona DNS. Si el servidor está mal configurado, revela todos los registros del dominio (hosts, subdominios, alias, etc.).

> Es una de las primeras pruebas a realizar contra un servidor DNS: si funciona, obtenemos un mapa completo de la infraestructura.

```bash
dig @<IP> dominio.dominio axfr
```
