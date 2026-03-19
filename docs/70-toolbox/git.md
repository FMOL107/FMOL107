---
title: Git
id: git
---

Guía rápida de Git: los comandos esenciales para el día a día.

## Conceptos clave

Git maneja tres "zonas" para tus archivos:

| Zona | Descripción |
|---|---|
| **Working directory** | Tu carpeta local, los archivos tal como los ves |
| **Staging area (index)** | Zona intermedia donde preparas lo que irá en el próximo commit |
| **Repository (.git)** | Historial de commits ya guardados |

El flujo básico es: **editar** → **stage** (`git add`) → **commit** (`git commit`).

## Configuración inicial

```bash
git config --global user.name "Tu Nombre"
git config --global user.email "tu@email.com"
```

## Crear / clonar un repositorio

```bash
# Inicializar un repo nuevo
git init

# Clonar un repo existente
git clone https://github.com/usuario/repo.git
```

## Ver el estado actual

```bash
# Ver qué archivos han cambiado, cuáles están en staging, cuáles sin trackear
git status

# Ver cambios en working directory (aún no en staging)
git diff

# Ver cambios que ya están en staging (listos para commit)
git diff --staged
```

> `git diff` muestra lo que has cambiado pero **no** has añadido con `git add`.
> `git diff --staged` muestra lo que **sí** has añadido y se incluirá en el próximo commit.

## Añadir archivos al staging area

```bash
# Añadir un archivo concreto
git add archivo.txt

# Añadir varios archivos
git add archivo1.txt archivo2.txt

# Añadir todo lo modificado y nuevo
git add .

# Añadir de forma interactiva (seleccionar trozos de un archivo)
git add -p archivo.txt
```

## Hacer commits

```bash
# Commit con mensaje inline
git commit -m "descripción del cambio"

# Commit con editor (para mensajes más largos)
git commit

# Añadir al staging + commit en un solo paso (solo archivos ya trackeados)
git commit -am "mensaje"
```

## Ver el historial

```bash
# Log completo
git log

# Log compacto (una línea por commit)
git log --oneline

# Log con grafo de ramas
git log --oneline --graph --all

# Ver qué cambió en un commit concreto
git show <commit-hash>

# Ver quién modificó cada línea de un archivo
git blame archivo.txt
```

## Ramas (branches)

```bash
# Ver ramas locales
git branch

# Crear una rama nueva
git branch nueva-rama

# Cambiar a otra rama
git checkout otra-rama
# o (más moderno)
git switch otra-rama

# Crear y cambiar en un solo paso
git checkout -b nueva-rama
# o
git switch -c nueva-rama

# Eliminar una rama (ya mergeada)
git branch -d rama-vieja

# Eliminar una rama (forzado, aunque no esté mergeada)
git branch -D rama-vieja
```

## Merge y rebase

```bash
# Merge: incorporar cambios de otra rama a la actual
git merge otra-rama

# Rebase: reaplicar tus commits encima de otra rama (historial más limpio)
git rebase main
```

> **Merge** crea un commit de merge. **Rebase** reescribe el historial — no usar en ramas compartidas.

## Deshacer cambios

```bash
# Descartar cambios en working directory (volver al último commit)
git restore archivo.txt

# Quitar un archivo del staging (sin perder los cambios)
git restore --staged archivo.txt

# Deshacer el último commit pero mantener los cambios en staging
git reset --soft HEAD~1

# Deshacer el último commit y quitar del staging (cambios quedan en working dir)
git reset HEAD~1

# Deshacer el último commit y BORRAR los cambios (destructivo)
git reset --hard HEAD~1
```

:::danger
`git reset --hard` es **irreversible**. Se pierden los cambios no commiteados.
:::

## Stash: guardar cambios temporalmente

```bash
# Guardar cambios actuales en el stash
git stash

# Ver lista de stashes
git stash list

# Recuperar el último stash
git stash pop

# Recuperar sin eliminarlo del stash
git stash apply
```

Útil cuando necesitas cambiar de rama pero no quieres hacer commit de un trabajo a medias.

## Remotos (push, pull, fetch)

```bash
# Ver remotos configurados
git remote -v

# Añadir un remoto
git remote add origin https://github.com/usuario/repo.git

# Subir cambios al remoto
git push origin main

# Subir y vincular la rama local con la remota (-u solo la primera vez)
git push -u origin mi-rama

# Traer cambios del remoto y mergear
git pull

# Traer cambios sin mergear (solo descargar)
git fetch
```

> `git pull` = `git fetch` + `git merge`. Si prefieres más control, usa `fetch` + `merge`/`rebase` por separado.

## .gitignore

Archivo en la raíz del repo que indica qué archivos/carpetas ignorar:

```text
# Ignorar archivos de entorno
.env
*.log

# Ignorar carpetas
node_modules/
build/
__pycache__/

# Ignorar un archivo concreto
secrets.txt
```

## Resumen visual

```
 Working Dir     Staging Area     Repository      Remote
     |                |               |               |
     |--- git add --->|               |               |
     |                |-- git commit->|               |
     |                |               |--- git push-->|
     |                |               |               |
     |<-------------- git pull -------|<-- fetch -----|
     |<- git restore -|               |               |
     |                |<-- reset -----|               |
```
