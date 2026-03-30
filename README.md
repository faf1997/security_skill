# Security Skill (OpenClaw)

Repositorio con una skill de seguridad para OpenClaw enfocada en **endurecer agentes** con un checklist obligatorio y un **gate** de reinicio del gateway.

## Índice

- [¿Para qué?](#para-qué)
- [¿Por qué?](#por-qué)
- [¿Cómo?](#cómo)
- [Instalación](#instalación)
- [Pruebas y casos de uso](#pruebas-y-casos-de-uso)
- [Mejoras futuras](#mejoras-futuras)

## ¿Para qué?

- Evitar que agentes nuevos/actualizados queden con permisos peligrosos (por error u omisión).
- Forzar guardrails mínimos para `exec` (allowlist/denylist) cuando se habilita.
- Hacer que el **reinicio** del gateway ocurra **solo** si el checklist pasa (sin warnings).

## ¿Por qué?

- Los cambios de agentes/config tienden a crecer “orgánicamente” y el riesgo se acumula.
- Un agente con `exec` + mensajería abierta es una superficie de ataque enorme.
- Un gate determinístico (script) es más confiable que “acordarse” de revisar a mano.

## ¿Cómo?

Esta skill aporta dos piezas:

1) **Validador**: `enforce_agent_security.py`
- Audita `/home/node/.openclaw/openclaw.json`
- Devuelve exit codes:
  - `0` PASS
  - `1` WARN
  - `2` FAIL

2) **Wrapper**: `agent_change_wrapper.py`
- Corre el validador
- **Solo si PASS (0)** reinicia el gateway
- Si WARN (1) o FAIL (2) **no** reinicia
- Política: **no warnings allowed** (WARN bloquea igual que FAIL)

Checklist humano (fuente de verdad): `skills/public/agent-security-checklist/references/checklist.md`

## Instalación

### Opción A — Copiar la skill al workspace

Copiá la carpeta de la skill dentro del workspace que use tu agente principal:

- `skills/public/agent-security-checklist/`

Ejemplo (ajustá paths según tu instalación):

```bash
cp -a skills/public/agent-security-checklist /home/node/.openclaw/workspace-main/skills/public/
```

### Opción B — Usar este repo como fuente

Cloná el repo en el host donde corre OpenClaw y copiá la skill al workspace correspondiente.

> Nota: el mecanismo exacto de “instalación de skills” puede variar según cómo tengas configurado OpenClaw (skills bundled vs skills locales). La parte importante es que la ruta de la skill quede accesible donde vayas a ejecutar los scripts.

## Pruebas y casos de uso

### Caso 1 — Cambié `openclaw.json` y quiero aplicar el cambio de forma segura

1) Editás `/home/node/.openclaw/openclaw.json`
2) Corrés el wrapper:

```bash
python3 skills/public/agent-security-checklist/scripts/agent_change_wrapper.py \
  --config /home/node/.openclaw/openclaw.json
```

Resultados esperados:
- Si el checklist pasa: reinicia gateway.
- Si hay WARN/FAIL: imprime hallazgos y **no** reinicia.

### Caso 2 — Quiero correr solo el validador (CI / pre-commit)

```bash
python3 skills/public/agent-security-checklist/scripts/enforce_agent_security.py \
  --config /home/node/.openclaw/openclaw.json
```

Usos típicos:
- CI: bloquear merge si el exit code != 0
- pre-commit hook: bloquear commit si el exit code != 0

### Caso 3 — “Dry run” del wrapper (sin reiniciar)

```bash
python3 skills/public/agent-security-checklist/scripts/agent_change_wrapper.py --no-restart
```

### Casos de fallo que debería detectar

- Un agente tiene `tools.alsoAllow: ["exec"]` pero no existe `openclaw-security.config.exec.policies[agentId]`.
- `defaultPolicy` no niega metacaracteres (riesgo de chaining/injection).
- `tools.elevated.enabled=true` pero `allowFrom` contiene `*`.
- Allowlist excesivamente amplia (`.*`, `^.*$`, etc.).

## Mejoras futuras

- **Runner “shell=false”**: reemplazar regex allowlist por un runner de acciones (intents) validado estrictamente.
- **Autofix / patch generator**: modo `--fix` que proponga cambios seguros en `openclaw.json` (sin aplicarlos automáticamente).
- **Integración nativa en OpenClaw**: hook/plugin que corra el checklist automáticamente ante cambios en `agents.list` (en vez de wrapper externo).
- **Reglas de comunicación entre agentes**: allowlist de `sessions_send`/destinos y prevención de “tool laundering”.
- **Políticas por canal**: checks más estrictos para WhatsApp/Telegram/Slack según exposición y bindings.
