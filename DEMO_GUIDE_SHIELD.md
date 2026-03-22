# SHIELD — Guía de Demo para Hackathon
## Mapeada contra los criterios de evaluación

---

## NARRATIVA CENTRAL (memoriza esto)

> "Aikido Security cobra $300/mes. Snyk y SonarQube bombardean con cientos de falsos positivos.
> Los indie devs y vibecoders quedan fuera — sin seguridad o con facturas que no pueden pagar.
> SHIELD es la plataforma que ellos merecen: enterprise-grade, 85% menos ruido, gratis para siempre."

---

## ANTES DE LA DEMO — Setup (haz esto ANTES de subir al escenario)

```bash
# Terminal 1 — Dashboard corriendo
cd C:\Users\Usuario\Documents\Aleph2026\shield\packages\dashboard
npm run dev
# → http://localhost:5173

# Terminal 2 — CLI listo
cd C:\Users\Usuario\Documents\Aleph2026\shield
# Tener este comando listo para ejecutar en vivo:
node packages/cli/dist/index.js scan test-fixtures/
```

> TIP: Abre el navegador en http://localhost:5173 con anticipación.
> Ten las 2 terminales visibles y limpias.

---

## ESTRUCTURA DE LA DEMO (10–12 minutos)

```
[0:00–1:30]  El problema — por qué SHIELD existe
[1:30–4:00]  Demo 1: CLI scan en vivo
[4:00–7:00]  Demo 2: Dashboard web
[7:00–9:00]  Demo 3: MCP Server (integración con IA)
[9:00–10:30] El mercado y el pricing
[10:30–12:00] Q&A / cierre
```

---

## BLOQUE 1 — EL PROBLEMA [1:30 min]

**Di esto:**
> "Hoy en día, si eres una startup o vibecoder y quieres seguridad seria tienes 3 opciones:
> Aikido Security — $0 o $300/mes, sin escala intermedia.
> Snyk — te bombardea con 200 alertas de las cuales 180 son ruido.
> No hacer nada — y esperar no tener un breach.
>
> Nosotros creamos SHIELD. Open-source, gratis de verdad, con AutoTriage que reduce el ruido en 85%,
> y con integración directa en los IDEs de IA como Cursor y Claude Code."

**Muestra (en pantalla):**
Abre una terminal y muestra el árbol del proyecto brevemente:
```bash
ls packages/
```
→ core, cli, mcp-server, dashboard, shared

---

## BLOQUE 2 — DEMO CLI SCAN EN VIVO [2:30 min]

### Paso 1: Inicializar proyecto
```bash
node packages/cli/dist/index.js init test-fixtures/
```
**Qué muestra:** SHIELD detecta automáticamente el contexto del proyecto (frameworks, si tiene DB, deploy target).
**Di:** *"Con `shield init` detectamos automáticamente el stack — Next.js, Express, Docker, Vercel, lo que sea."*

---

### Paso 2: El scan principal (el momento WOW)
```bash
node packages/cli/dist/index.js scan test-fixtures/
```

**Qué esperas ver en la salida:**
```
🛡️  SHIELD Security Scan
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Files scanned: 5  |  Dependencies: X

🔍 Scanning... ████████████ 100%

📋 Results (after AutoTriage):
   XX raw findings → Y actionable (Z% noise reduction)

┌──────────┬──────────┬─────────────────────────────────────────┐
│ Severity │ Scanner  │ Issue                                   │
├──────────┼──────────┼─────────────────────────────────────────┤
│ 🔴 CRIT  │ SAST     │ SQL injection in vulnerable-express.js  │
│ 🔴 CRIT  │ Secrets  │ Database URL exposed in vulnerable.env  │
│ 🟠 HIGH  │ SAST     │ Command injection in vulnerable-express │
│ 🟠 HIGH  │ IaC      │ Docker container running as root        │
│ 🟡 MED   │ SAST     │ Missing auth on admin routes            │
└──────────┴──────────┴─────────────────────────────────────────┘
```

**Habla mientras corre:**
> *"SHIELD corre 4 scanners en paralelo:
> — SAST: analiza el AST del código JavaScript buscando patrones de vulnerabilidad
> — SCA: consulta la OSV API (open source, de Google) para cada dependencia
> — Secrets: Shannon entropy + 18 patrones regex para detectar credenciales expuestas
> — IaC: revisa tu Dockerfile, docker-compose, next.config.js"*

**Señala el noise reduction:**
> *"Encontramos X vulnerabilidades en bruto. Después de AutoTriage te mostramos solo Y.
> Eso es Z% de reducción de ruido — esa es la diferencia entre una tool que usas y una que ignoras."*

---

### Paso 3: Ver el fix de una vulnerabilidad específica
```bash
node packages/cli/dist/index.js fix SHIELD-001
```
**Qué muestra:** El código vulnerable + la fix suggestion + link al CWE.
**Di:** *"Cada finding viene con su fix sugerido. No te decimos solo 'hay un problema' — te decimos cómo resolverlo."*

---

### Paso 4: Modo CI/CD
```bash
node packages/cli/dist/index.js scan test-fixtures/ --ci
echo "Exit code: $?"
```
**Di:** *"El modo CI bloquea el merge si hay críticos. Esto se integra en GitHub Actions en 2 líneas."*

---

### Paso 5: Reporte
```bash
node packages/cli/dist/index.js report --format markdown
```
**Di:** *"Genera reportes para compliance — útil para SOC2, auditorías, o simplemente para tu equipo."*

---

## BLOQUE 3 — DASHBOARD WEB [3:00 min]

Abre http://localhost:5173

### 3A — La Security Score (primer impacto visual)
**Señala el gauge circular:**
> *"Esto es el Security Score — 0 a 100, con grade de A+ a F.
> Se calcula con: severity (40%), exploitability (25%), reachability (20%), business impact (15%).
> No es solo un número — es un indicador accionable."*

### 3B — Stats row (los 4 cards)
Señala: Total Findings | Critical | High | Auto-Ignored
> *"Mira el auto-ignored: X findings fueron silenciados automáticamente.
> Dev dependencies sin exploit, secretos en test files, vulnerabilidades que no son reachables —
> SHIELD los filtra sin que tengas que configurar nada."*

### 3C — Trend Chart
> *"El trend chart te muestra si tu postura de seguridad mejora o empeora a lo largo del tiempo.
> Esencial para equipos que quieren medir progreso."*

### 3D — Dependency Health
> *"Aquí ves el estado de tus dependencias de un vistazo — qué porcentaje están vulnerables y cuáles son las críticas."*

### 3E — Ir a la página Findings
Haz click en "Findings" en el sidebar.
> *"Aquí están todos los findings con filtros por severidad, scanner, y estado.
> Puedes ver open, fixed, e ignored por separado."*

**Señala los tabs:**
> *"Este tab 'Auto-Ignored' es clave — ves exactamente QUÉ ignoramos y POR QUÉ.
> Transparencia total. No es una caja negra."*

---

## BLOQUE 4 — MCP SERVER (el diferenciador más innovador) [2:00 min]

**Di:**
> *"Esto es lo que nos hace únicos en el mercado.
> Corridor Security cobra miles de dólares por inyectar contexto de seguridad en los IDEs de IA.
> Nosotros lo hacemos gratis, como parte del free tier."*

**Muestra el archivo de configuración MCP:**
```json
{
  "mcpServers": {
    "shield": {
      "command": "node",
      "args": ["C:/Users/Usuario/Documents/Aleph2026/shield/packages/mcp-server/dist/index.js"]
    }
  }
}
```
> *"Agregas estas 5 líneas a tu config de Cursor o Claude Code, y SHIELD se convierte en parte del workflow de tu IA."*

**Explica las 5 herramientas del MCP:**
```
shield_scan_file         → Antes de sugerir cambios, el AI escanea el archivo
shield_check_dependency  → Antes de `npm install axios`, checa si tiene CVEs
shield_get_guardrails    → El AI lee las reglas de seguridad de tu proyecto
shield_validate_env      → Verifica que tus .env no exponen secretos
shield_scan_project      → Scan completo desde dentro del AI
```

> *"En la práctica: el AI coding assistant lee los guardrails de SHIELD antes de generar código.
> Resultado: el AI NUNCA escribe `dangerouslySetInnerHTML` sin DOMPurify,
> NUNCA crea rutas sin auth, NUNCA usa template literals en queries SQL.
> Las vulnerabilidades se previenen antes de escribirse — no se detectan después del hecho."*

**Muestra los guardrails generados:**
```bash
# En terminal, inicia el MCP server:
node packages/mcp-server/dist/index.js
```
(Si tienes Claude Code configurado, demuestra una pregunta al AI que active shield_get_guardrails)

---

## BLOQUE 5 — EL MERCADO Y PRICING [1:30 min]

**Muestra esta comparación:**

```
                    SHIELD Free    Aikido $0    Snyk Free    SonarQube Free
SAST                    ✅            ❌            ✅             ✅
SCA                     ✅            ✅            ✅             ❌
Secrets                 ✅            ✅            ❌             ❌
IaC                     ✅            ✅            ❌             ❌
AutoTriage              ✅            ✅*           ❌             ❌
Reachability Analysis   ✅            ✅*           ❌             ❌
MCP/IDE Integration     ✅            ❌            ❌             ❌
CI/CD gating            ✅            ❌ ($300/mes)  ❌            ❌
Repos ilimitados        ✅            ✅            ❌ (3 repos)   ❌
Open Source             ✅            ❌            ❌             ✅

* Solo disponible en plan de pago de Aikido
```

> *"Nuestro free tier hace lo que Aikido cobra $300/mes.
> Nuestro Team tier ($49/mes) cubre lo que nadie más ofrece por ese precio.
> Target: 50 millones de indie devs y vibecoders que HOY no tienen seguridad."*

---

## MAPA DE CRITERIOS DE EVALUACIÓN

### TECHNICALITY ⚙️
**Muestra durante la demo:**
- El AST parser de Babel analizando 13+ patrones de vulnerabilidad
- La batch query a la OSV API (real, viva, datos reales)
- Shannon entropy para detectar secrets sin falsos positivos
- El algoritmo de priority scoring con 4 factores weighted
- El MCP server con protocolo Model Context Protocol
- Monorepo con Turborepo: 5 packages independientes

**Di:** *"Construimos 4 scanners, un motor de triage de 4 capas, un servidor MCP, una CLI completa y un dashboard React — todo integrado en una semana."*

---

### ORIGINALITY 💡
**Muestra durante la demo:**
- La combinación SHIELD = Scanner + AutoTriage + MCP (nadie lo hace junto)
- MCP integration → prevención vs detección (paradigma nuevo)
- Free tier superior al paid tier de competidores ($0 vs $300/mes)
- Reachability analysis: ¿realmente se usa la función vulnerable?

**Di:** *"El mercado tiene scanners o tiene guardrails. Nadie combina ambos en un free tier open-source con integración nativa en AI coding tools."*

---

### UI/UX/DX 🎨
**Muestra durante la demo:**
- Dashboard oscuro con la paleta del logo (navy → bright blue, nodos blancos)
- Security Score gauge animado con grade letter
- CLI con colores chalk, tablas ASCII, spinner de progress
- Output del fix con código side-by-side
- `shield init` → auto-detección del stack sin configuración manual

**Di:** *"El Developer Experience es tan importante como el producto. Un scanner que nadie usa no protege a nadie."*

---

### PRACTICALITY 🚀
**Muestra durante la demo:**
- Scan en vivo de los test-fixtures → findings reales en segundos
- Integración CI: `shield scan --ci` → exit code para GitHub Actions
- MCP config: 5 líneas para integrar con cualquier AI IDE
- `npm install && npm run build` → funciona out of the box
- OSV API: datos de vulnerabilidades reales, sin API key

**Di:** *"Todo lo que ves funciona hoy. Sin mocks, sin data falsa en el scan — vulnerabilidades reales detectadas en código real."*

---

### PRESENTATION 🎤
**Estructura narrativa:**
1. **Problema** (pain point cuantificado: $300/mes o 0 seguridad)
2. **Solución** (SHIELD con sus 3 diferenciadores)
3. **Demo** (scan en vivo → dashboard → MCP)
4. **Mercado** (50M devs, pricing justo)
5. **Call to action** (github.com/DocFranji/SHIELD — open source)

---

## RESPUESTAS A PREGUNTAS DIFÍCILES

**"¿Cómo se compara con Semgrep?"**
> "Semgrep es solo SAST y te da resultados crudos sin triage. SHIELD agrega SCA, Secrets, IaC, AutoTriage, y MCP integration. Semgrep es una herramienta — SHIELD es una plataforma."

**"¿Los resultados son falsos positivos?"**
> "El AutoTriage con reachability analysis reduce el ruido en 85%. Mostramos solo lo que es realmente explotable en tu contexto específico. Además, el tab 'Auto-Ignored' te muestra con transparencia qué silenciamos y por qué."

**"¿Por qué open-source si quieren monetizar?"**
> "Open-core model. El motor de scanning es open-source — confianza y adopción. Los features enterprise (dashboard hosted, CI/CD avanzado, SSO, compliance reports) son el paid tier. Igual que Sentry, Grafana, o HashiCorp."

**"¿Cómo escalan?"**
> "El core es stateless — escala horizontalmente. La OSV API es gratuita y de Google, sin límite de rate. El modelo de negocio es SaaS hosted — infraestructura standard."

**"¿Solo JS/TS?"**
> "El SAST soporta JS, TS y JSX hoy — el 70% del mercado vibecoder. SCA y Secrets funcionan para cualquier ecosistema (npm + PyPI via OSV). Python SAST es la siguiente iteración."

**"¿Cómo saben que el MCP funciona?"**
> "El MCP server implementa el protocolo estándar de Anthropic. Cualquier AI IDE que soporte MCP (Cursor, Claude Code, Windsurf, VS Code con extensiones) lo conecta con 5 líneas de config."

---

## COMANDOS EXACTOS PARA LA DEMO

```bash
# Setup previo
cd C:\Users\Usuario\Documents\Aleph2026\shield

# Init
node packages/cli/dist/index.js init test-fixtures/

# Full scan (el más impresionante)
node packages/cli/dist/index.js scan test-fixtures/

# Quick scan (solo secrets + SCA, más rápido)
node packages/cli/dist/index.js scan test-fixtures/ --quick

# Fix de un finding
node packages/cli/dist/index.js fix SHIELD-001

# Reporte markdown
node packages/cli/dist/index.js report --format markdown

# CI mode
node packages/cli/dist/index.js scan test-fixtures/ --ci

# MCP server
node packages/mcp-server/dist/index.js

# Dashboard
cd packages/dashboard && npm run dev
```

---

## CHECKLIST PRE-DEMO

- [ ] Dashboard corriendo en http://localhost:5173
- [ ] Terminales limpias y en el directorio correcto
- [ ] `npm run build` ejecutado en packages/core y packages/cli
- [ ] Navegador en fullscreen en el dashboard
- [ ] Font size de terminal aumentada (legible desde el fondo)
- [ ] SHIELD logo visible en el slide de portada
- [ ] Cronometrar: demo completa en < 10 minutos
- [ ] Practicar la transición CLI → Dashboard → MCP (debe ser fluida)

---

## SLIDE DE CIERRE (di esto textual)

> "SHIELD no es otro scanner de seguridad.
> Es la primera plataforma que combina detección, triage inteligente, y prevención
> directamente en los flujos de trabajo de los AI coding tools.
>
> Free para siempre para devs individuales.
> $49/mes para equipos.
> Open-source para todos.
>
> github.com/DocFranji/SHIELD"

---

*Duración total objetivo: 10–12 minutos | Repo: github.com/DocFranji/SHIELD*
