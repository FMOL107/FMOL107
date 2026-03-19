---
id: msrpc
title: MSRPC - 135,593
---

MSRPC (Microsoft Remote Procedure Call) permite la comunicación entre procesos en red. El puerto 135 es el endpoint mapper y revela servicios RPC disponibles. A través de `rpcclient` se puede enumerar usuarios, grupos y políticas de un dominio Active Directory.

## Rpcclient enumeration

### Null session

Conexión sin credenciales. Si el servidor lo permite, se pueden enumerar usuarios y grupos del dominio.

> Comandos útiles dentro de rpcclient: `enumdomusers`, `enumdomgroups`, `querygroupmem`, `queryuser`, `querydispinfo`.

```bash
rpcclient -U "" <IP> -N
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querygroupmem <rid>
rpcclient $> queryuser <rid>
rpcclient $> querydispinfo
```

Modo no interactivo con `-c` para ejecutar un comando directamente:

```bash
rpcclient -U "" <IP> -N -c 'enumdomusers'
rpcclient -U "" <IP> -N -c 'enumdomgroups'
```

### Usuario y contraseña

Enumeración autenticada. Devuelve información más completa que una null session.

```bash
rpcclient -U "user%password" <IP> -c 'enumdomusers'
rpcclient -U "user%password" <IP> -c 'querydispinfo'
```

### Usuario y hash

Autenticación con hash NTLM (pass-the-hash). Útil cuando se dispone de un hash pero no de la contraseña en texto claro.

```bash
rpcclient -U "user%hash" --pw-nt-hash <IP>
```


https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc