---
title: Buffer Overflow
id: bof
---

Metodologia clasica de buffer overflow para binarios x86 en Windows, usando Immunity Debugger y el plugin mona.

> Util para CTFs tipo OSCP/TryHackMe donde se explota un BoF stack-based vanilla.

### Herramientas necesarias

- https://github.com/kbandla/ImmunityDebugger — Debugger para Windows donde se ejecuta mona.
- https://github.com/corelan/mona — Plugin de Immunity para automatizar pasos del BoF (bad chars, JMP ESP, etc).

Copia `mona.py` en la carpeta de PyCommands de Immunity:

```
C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands
```

### Preparar la maquina victima

Desactiva DEP en la maquina Windows de pruebas para que el exploit funcione:

```cmd
BCDEDIT /SET {CURRENT} NX ALWAYSOFF
```

### Script de referencia

https://gist.github.com/s4vitar/**b88fefd5d9fbbdcc5f30729f7e06826e

Gatekeeper

## Comandos mona

### Configurar espacio de trabajo

Define la carpeta de trabajo donde mona guardara los ficheros generados (bytearrays, logs, etc).

```
!mona config -set workingfolder C:\Users\fmol\Documents\%p
```

### Generar bytearray

Genera un bytearray para identificar bad chars. Compara con el dump en memoria para ver cuales corrompen el payload.

```
!mona bytearray
```

### Comparar bad chars

Compara el bytearray generado con el contenido en memoria en la direccion del ESP para detectar bad chars.

```bash
!mona compare -f C:\Users\fmol\Documents\gatekeeper\bytearray.bin -a 009B19E4
```

### Listar modulos

Lista los modulos cargados y sus protecciones (ASLR, SafeSEH, etc). Busca uno sin protecciones para encontrar un JMP ESP fiable.

```
!mona modules
```

### Buscar JMP ESP

Busca la instruccion `JMP ESP` (`\xff\xe4`) dentro del modulo vulnerable. Esta direccion sera el EIP de tu exploit.

```
!mona find -s "\xff\xe4" -m gatekeeper.exe
```



