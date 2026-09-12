# SOAR export guide

Phishbowl can export a completed triage as a **playbook draft** for two SOAR
platforms — **Cortex XSOAR** and **Microsoft Sentinel**. This is Phase 6 of the
[checklist](CHECKLIST.md) and implements [PRD §6.6](PRD.md).

> [!IMPORTANT]
> **These exports are drafts. Phishbowl never acts.**
> An export is a starting-point playbook, seeded with the verdict and indicators,
> that an analyst **reviews and runs** in their own platform. Phishbowl itself
> never quarantines, blocks, sends, replies, detonates, fetches the email's URLs,
> or auto-remediates ([CLAUDE.md](../CLAUDE.md) / [PRD §4](PRD.md)). The artifacts
> are inert *by construction* — and the guarantee is enforced by their schemas, not
> just asserted in prose (see [Why these are safe](#why-these-are-safe-by-construction)).

---

## Quick start

```bash
# Offline triage → both SOAR drafts (zero API keys)
phishbowl analyze suspicious.eml \
  --xsoar    playbook.yml \
  --sentinel azuredeploy.json

# Combine with anything else: HTML report, JSON, redaction, enrichment
phishbowl analyze suspicious.eml --xsoar pb.yml --redact
```

| Flag | Platform | Artifact | Format |
|------|----------|----------|--------|
| `--xsoar PATH` | Cortex XSOAR (6.x+) | Playbook (manual tasks) | YAML |
| `--sentinel PATH` | Microsoft Sentinel | Playbook = Logic App, as an ARM deployment template | JSON |

Both reuse the same prepared report view as the HTML/JSON/CLI outputs, so
**defanging, PII redaction (`--redact`), severity, and enrichment status stay
identical across every output**. Nothing in the export path touches the network.

### Two channels: raw vs. defanged

Every export carries indicators twice, deliberately — the same dual-channel
contract the JSON report uses:

- **Raw** values feed the *machine* fields a SOAR actually pivots and hunts on
  (XSOAR playbook **inputs**; the Sentinel `indicators_raw` object). Redacted
  indicators (bystander PII) are dropped from this channel entirely.
- **Defanged** values (`hxxps://evil[.]com`) feed every *human-readable* note, so
  reading the exported YAML/JSON in an editor never hands you a live link.

`--redact` withholds bystander recipients and internal hostnames/IPs from **both**
channels while keeping the attacker's indicators fully intact.

---

## Cortex XSOAR playbook

The artifact is an XSOAR 6.x **playbook** YAML — the format you upload under
**Playbooks → Upload**. It is a linear chain of **manual tasks** (an analyst
checklist); no task binds an automation command.

### Import steps

1. In XSOAR, go to **Playbooks** and click **Upload** (top-right).
2. Select the exported `playbook.yml`.
3. Open the imported playbook. Every task is a **manual** task — review the
   verdict, indicators, and authentication notes it carries.
4. The raw indicators are attached as playbook **inputs** (e.g. `PhishbowlUrls`,
   `PhishbowlFileHashes`). Wire them into your own (reviewed) sub-playbooks or
   commands *if and when you decide to act* — the draft never does so for you.

### Field mapping

| XSOAR playbook field | Source (from `ParsedEmail` + verdict + IOCs) |
|----------------------|----------------------------------------------|
| `name` | `"Phishbowl Triage — <verdict> (DRAFT)"` |
| `description` | Disclaimer + verdict/score/auth/indicator-count summary |
| `tags` | `phishbowl`, `phishing`, `triage`, `draft`, `manual`, `no-auto-remediation` |
| `tasks["0"]` (`start`) | Mandatory start node |
| `tasks["1"]` (`title`) | "Phishbowl Triage (DRAFT — review before acting)" |
| `tasks` (`regular`, manual) | Review verdict · Review indicators (defanged) · Review authentication · Decide containment (manual) |
| `tasks[*].task.iscommand` | Always `false` — **no command binding** |
| `tasks[*].task.brand` | Always `""` — **no integration bound** |
| `inputs[].PhishbowlVerdict` | Verdict band text |
| `inputs[].PhishbowlScore` | `"<score>/100"` |
| `inputs[].PhishbowlUrls` / `Domains` / `Ips` / `Emails` / `FileHashes` | **Raw** indicators (comma-separated), redaction-respecting; file hashes include attachment MD5/SHA1/SHA256 |
| task note: "Why this score" | Each fired rule: description, defanged evidence, weight, source tag |
| task note: indicators | Defanged URLs / domains / IPs / emails / hashes |
| task note: authentication | SPF / DKIM / DMARC results |

---

## Microsoft Sentinel playbook

A Microsoft Sentinel *playbook* is an **Azure Logic App**, deployed via an Azure
Resource Manager (ARM) template. The artifact is that deployment template
(`azuredeploy.json`). It deploys the workflow **disabled**, behind a **manual**
trigger, with only inert `Compose` actions that hold the triage data.

### Import / deploy steps

1. **Review the template first.** It is plain JSON — read the `Compose` action
   named `Compose_Phishbowl_Triage_DRAFT`; that is the whole triage object.
2. Deploy it like any ARM template, e.g. with the Azure CLI:
   ```bash
   az deployment group create \
     --resource-group <your-rg> \
     --template-file azuredeploy.json
   ```
   The template's default `PlaybookName` is **unique per analysis**
   (`Phishbowl-Triage-Draft-<analysis-seed>`), so deploying drafts for several
   messages into the same resource group creates distinct Logic Apps instead of
   overwriting one another. Pass `--parameters PlaybookName=<your-name>` to
   override. (Or **Sentinel → Automation → Create → Playbook with Logic App**,
   then paste the workflow definition; or use **Template spec / Deploy a custom
   template** in the portal.)
3. The Logic App is created **Disabled**. Open it in the Logic App designer,
   review every action, and replace the inert `Compose` steps with your own
   (reviewed) response actions if you choose to.
4. Only **you** enable it. Until you do, it cannot run.

### Field mapping

| Sentinel / ARM field | Source |
|----------------------|--------|
| `$schema` | ARM deployment-template schema |
| `parameters.PlaybookName` | Logic App name (default `Phishbowl-Triage-Draft`) |
| `resources[0].type` | `Microsoft.Logic/workflows` |
| `resources[0].properties.state` | Always `"Disabled"` — **ships off** |
| `parameters.PlaybookName.defaultValue` | `Phishbowl-Triage-Draft-<analysis-seed>` — unique per analysis |
| `…definition.triggers` | Exactly one manual HTTP `Request` trigger — **not** an automatic Sentinel alert/incident trigger |
| `…actions` | Inert `Compose` actions only (each `type` is `Compose`) |
| `…actions.Compose_Phishbowl_Triage_DRAFT.inputs` | The full triage object (below) |
| `…actions.Compose_Draft_Notice` | The never-acts disclaimer, surfaced on its own |
| `…outputs.PhishbowlVerdict` | `"<verdict> (<score>/100)"` |

The triage object inside the `Compose` action carries:

| Key | Source |
|-----|--------|
| `disclaimer`, `draft`, `never_acts` | The never-acts framing |
| `verdict` | `{text, score, offline_score, max_score, severity}` |
| `subject`, `sender` | Defanged subject; sender display/address (raw + defanged)/domain |
| `authentication` | SPF / DKIM / DMARC `{mechanism, result, detail}` |
| `reasons` | Every fired rule `{id, description, weight, source, evidence}` |
| `indicators_raw` | **Raw** indicators by bucket — for hunting (redaction-respecting) |
| `indicators_defanged` | The human-safe mirror |
| `redaction`, `enrichment` | Whether each was active, and which connectors ran |
| `recommended_review_draft` | The draft, analyst-driven review steps |

---

## Why these are safe by construction

The "never acts" invariant is enforced **three ways** — in code, in the prose
stamped into each artifact, and **structurally in the expected schema** — so a
future change that tried to make an export *act* would fail the validation tests:

- **XSOAR:** every task's `task.iscommand` is `const false`, and the task shape is
  *locked* (`additionalProperties: false`) in
  [`xsoar_playbook.schema.json`](../phishbowl/export/schemas/xsoar_playbook.schema.json),
  so a task can bind neither an integration command **nor** an automation script
  (`scriptName`/`scriptId`/`scriptarguments` and any other extra field are
  rejected). The schema proves the playbook is *manual-only*, not merely
  command-free.
- **Sentinel:** the workflow's `properties.state` is `const "Disabled"`, the
  `triggers` object permits **only** a manual `Request` trigger
  (`additionalProperties: false` — no recurrence or auto Sentinel-alert trigger),
  and every action's `type` must be the inert `Compose`
  (a connector / `Http` / `ApiConnection` action is rejected), in
  [`sentinel_playbook.schema.json`](../phishbowl/export/schemas/sentinel_playbook.schema.json).
  An enabled, auto-triggered, or remediating workflow cannot validate.

Each export is validated against its schema on every bundled fixture in
[`tests/test_export.py`](../tests/test_export.py) (the Phase 6 DoD), and the same
tests prove the validator rejects a tampered artifact that flips either invariant —
so "it validates" genuinely means "it cannot auto-remediate."

### Validating an export yourself

The schemas are standard JSON Schema (draft 2020-12) and live under
[`phishbowl/export/schemas/`](../phishbowl/export/schemas/). Validate with any
JSON-Schema tool, or with Phishbowl's bundled (dependency-free) validator:

```python
import json, yaml
from phishbowl.export import validate_export, XSOAR_SCHEMA_NAME, SENTINEL_SCHEMA_NAME

playbook = yaml.safe_load(open("playbook.yml"))
template = json.load(open("azuredeploy.json"))

assert validate_export(playbook, XSOAR_SCHEMA_NAME) == []     # [] == conforms
assert validate_export(template, SENTINEL_SCHEMA_NAME) == []
```

## Literal email data and qualification

Sentinel string values that could be ARM or workflow expressions are represented
with a fixed `base64ToString` expression. Only base64 data enters its argument;
the decoded result is a string, not another expression. Other triage values remain
readable in the artifact. Playbook-name parameter defaults use ARM bracket escaping.
This follows Microsoft's [ARM expression rules](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-expressions)
and [workflow expression function reference](https://learn.microsoft.com/en-us/azure/logic-apps/expression-functions-reference).
The workflow remains disabled with manual triggers and Compose actions.

Synthetic tests check artifact structure and lossless string decoding. No Azure
or XSOAR deployment was performed during this review; the bundled schemas are
local structural checks, not complete vendor import certification. Inspect code
view after any edits in the Logic Apps designer, which can rewrite expressions.
`analysis_complete` and the assessment note accompany the Sentinel triage summary;
incomplete assessments are labeled in both platforms' draft verdicts.
