# roe-guard

[![CI](https://github.com/sametyilmaztemel/roe-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/sametyilmaztemel/roe-guard/actions/workflows/ci.yml)
[![Python ≥ 3.10](https://img.shields.io/badge/python-%E2%89%A53.10-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Rules of Engagement policy-enforcement library — scope, gate, log, clean.**

`roe-guard` lets a security operation (pentest, red team, autonomous
defence agent, CI remediation script) declare in YAML *which targets,
which time-windows, and which action types are allowed* — and
automatically blocks and audits every action that falls outside that
contract.

The reference implementation of 0rce Labs' *zero-unauthorized-operations*
principle: **scoped, gated, logged, cleaned**.

---

## Neden roe-guard?

In real engagements, scope creep — accidentally touching a production
subnet, scanning an out-of-contract IP — is the single biggest legal and
operational risk. roe-guard turns that discipline from a human
checklist into a few lines of code that any Python tool can call before
acting.

---

## Kurulum

> **Note:** roe-guard is not yet on PyPI. The package will be published
> as part of the v0.1 release (T9). Until then, install from source.

### Gereksinimler

- Python ≥ 3.10

### Kaynaktan (geliştirme)

```bash
git clone https://github.com/sametyilmaztemel/roe-guard.git
cd roe-guard
pip install -e ".[dev]"
```

### PyPI'den (yayınlandığında)

```bash
pip install roe-guard
```

### Doğrulama

```bash
$ roe-guard --version
roe-guard 0.1.0a1
```

---

## Hızlı Başlangıç

### 1. Bir politika yaz

`demo_policy.yaml`:

```yaml
engagement_id: "demo-acme-2026-08"
valid_from: "2020-01-01T00:00:00Z"
valid_until: "2030-01-01T00:00:00Z"

scope:
  allow:
    - cidr: "10.20.0.0/16"
    - hostname: "*.staging.acme.internal"
  deny:
    - cidr: "10.20.5.0/24"            # prod DB subnet — explicit carve-out

actions:
  allow: ["recon", "exploit", "persistence-test"]
  deny: ["destructive", "data-exfil"]

approval_required_for: ["persistence-test"]
```

> **Not:** Geçerli policy tarih aralığı (`2020–2030`) bilinçli olarak
> geniş tutulmuştur — README'deki örnekler hangi tarihte çalıştırılırsa
> çalıştırılsın, "policy expired" hatasına düşmesin diye. Gerçek
> engagement'larda `valid_from`/`valid_until` gerçek pencereye
> ayarlanmalı.

(Tam örnek için `tests/fixtures/demo_policy.yaml`)

### 2. Doğrula

```
$ roe-guard validate tests/fixtures/demo_policy.yaml
✓ Valid policy: demo-acme-2026-08 (2020-01-01T00:00:00+00:00 → 2030-01-01T00:00:00+00:00)
```

### 3. Karar al

```
$ roe-guard check --target 10.20.3.5 --action recon \
    --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.3.5
action:     recon
outcome:    ALLOW
reason:     action type 'recon' allowed
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 8.8.8.8 --action recon \
    --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     8.8.8.8
action:     recon
outcome:    DENY
reason:     target not in allowed scope
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 10.20.5.7 --action recon \
    --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.5.7
action:     recon
outcome:    DENY
reason:     target explicitly denied in scope
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 10.20.3.5 --action persistence-test \
    --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.3.5
action:     persistence-test
outcome:    REQUIRES_APPROVAL
reason:     action type 'persistence-test' requires human approval
timestamp:  2026-08-10T12:00:00+00:00
```

Exit codes: **0 = ALLOW, 1 = DENY, 2 = REQUIRES_APPROVAL**.

### 4. Python API'den çağır

```python
from datetime import datetime, timezone
from roe_guard.policy import load_policy
from roe_guard.models import Engagement
from roe_guard.engine import enforce
from roe_guard.exceptions import OutOfScopeError

policy = load_policy("tests/fixtures/demo_policy.yaml")
engagement = Engagement(policy=policy)
NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)

decision = engagement.check("10.20.3.5", "recon", now=NOW)
print(decision.outcome)  # DecisionType.ALLOW

# `raise_if_denied()` sadece DENY ise OutOfScopeError fırlatır
engagement.check("8.8.8.8", "recon", now=NOW).raise_if_denied()
# → OutOfScopeError: Denied: target='8.8.8.8' action='recon' reason=target not in allowed scope
```

### 5. Mevcut fonksiyonu `@guarded` ile koru

```python
from roe_guard.integrations.decorator import guarded


@guarded(engagement, action_type="recon", target_arg="host")
def scan(host: str) -> str:
    return f"scanned:{host}"


scan("10.20.3.5")  # → "scanned:10.20.3.5"
scan("8.8.8.8")  # → OutOfScopeError (wrapped fonksiyon hiç çağrılmadı)
```

### 6. Birden fazla aksiyonu `engagement.window()` ile toplu kontrol et

```python
from roe_guard.exceptions import OutOfScopeError

with engagement.window():
    for host in discovered_hosts:
        engagement.check(host, "recon").raise_if_denied()
        scan(host)
```

Bu örnekte `discovered_hosts = ["10.20.3.5", "10.20.3.6", "8.8.8.8"]`
olsa, ilk iki host taranır, `8.8.8.8` scope dışı olduğu için
`raise_if_denied()` `OutOfScopeError` fırlatır ve döngü kesilir.

### 7. Audit zinciri oluştur ve doğrula

```python
from roe_guard.audit import AuditLog

log = AuditLog("/var/log/roe-guard.jsonl")
for host, action in [("10.20.3.5", "recon"), ("8.8.8.8", "recon")]:
    d = engagement.check(host, action, now=NOW)
    log.record(d, engagement_id=policy.engagement_id)

result = log.verify()
# → AuditVerificationResult(valid=True, total_entries=2, ...)
```

```
$ roe-guard audit-verify /var/log/roe-guard.jsonl
✓ Audit chain valid (2 entries)
```

---

## CLI Referansı

| Komut | Argümanlar | Exit code | Açıklama |
|-------|-----------|-----------|----------|
| `validate` | `<policy.yaml>` | 0 = valid, 1 = invalid | YAML'ı parse eder, schema doğrular. |
| `check` | `--target T --action A --policy P [--now ISO8601]` | 0 = ALLOW, 1 = DENY, 2 = REQUIRES_APPROVAL | Bir (target, action) çiftini policy'ye karşı değerlendirir. |
| `audit-verify` | `<audit.jsonl>` | 0 = intact, 1 = broken | Hash zincirini doğrular, tahrif tespit eder. |

---

## Mimari

```
Policy YAML → load_policy() → Policy nesnesi
                                 ↓
                  Engagement (policy + operation_id)
                                 ↓
       enforce(eng, target, action) → Decision
                          ↓             ↓
              raise_if_denied()   audit.record()
                          ↓             ↓
                   OutOfScopeError   JSONL + SHA-256 zincir
```

Modüller:

- `models` — `Policy`, `Engagement`, `Decision`, `AuditEntry` (immutable dataclass'lar)
- `policy` — YAML yükleme + şema doğrulama (`yaml.safe_load`)
- `engine` — 8 adımlı fail-closed karar motoru (spec §5)
- `audit` — Append-only JSONL + SHA-256 hash zinciri
- `integrations` — `@guarded` decorator + `engagement.window()` context manager
- `cli` — `validate | check | audit-verify` (stdlib `argparse`, harici framework yok)
- `exceptions` — `OutOfScopeError`, `PolicyExpiredError`, `PolicyParseError`, `AuditIntegrityError`, `ApprovalRequiredError`

Tek bağımlılık: **pyyaml**. Spec için bkz. `docs/SPEC.md`.

---

## Tehdit Modeli / Sınırlamalar

roe-guard kendisi bir güvenlik aracıdır; sınırlarını açık söylemek
önemlidir.

1. **Bu bir ağ güvenlik duvarı değildir.** Sadece `enforce()` /
   `@guarded` çağıran araçları kısıtlar. Entegre etmeyen bir araç
   bypass edebilir. Bu bir SDK-seviyesi disiplin katmanıdır, ağ-seviyesi
   zorlama değildir.
2. **Audit log bütünlüğü** hash-chain ile tahrif tespiti sağlar,
   tahrifi önlemez. Dosya sistemine yazma erişimi olan biri log'u
   silebilir. v0.2'de opsiyonel harici anchor (imzalı uzak endpoint)
   düşünülüyor.
3. **Policy dosyası güvenilir bir kaynaktan gelmelidir.** YAML
   `safe_load` kullanıldığı için RCE riski yok, ama policy dosyasının
   kendisi yetkisiz değiştirilirse kapsam de facto genişleyebilir —
   dosya izinleri kullanıcı sorumluluğundadır.
4. **Fail-closed, fail-loud.** Policy parse edilemiyorsa veya süresi
   dolmuşsa her check DENY döner. "Emin değilsek izin ver" davranışı
   yoktur.

---

## Geliştirme

```bash
# Tüm testler
pytest

# Belirli bir test modülü
pytest tests/test_engine.py -v

# Ruff lint + format
ruff check roe_guard/ tests/
ruff format --check roe_guard/ tests/

# Demo'yu elle çalıştırmak
roe-guard validate tests/fixtures/demo_policy.yaml
roe-guard check --target 10.20.3.5 --action recon \
  --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
```

Coverage hedefi (spec §8): ≥ %85.

---

## Lisans

MIT — bkz. [LICENSE](LICENSE).

Built by [0rce Labs](https://github.com/orce-labs). v0.1 roadmap ve
tasarım kararları için bkz. [docs/SPEC.md](docs/SPEC.md).

---

> **Branch Koruması:** `main` branch'ine doğrudan push kapatılmıştır.
> Tüm değişiklikler `ticket/T<N>-<slug>` formatında branch + Pull
> Request üzerinden merge edilmelidir. Bu ayar GitHub Settings →
> Branches → Branch protection rules üzerinden yapılandırılmıştır.
> Commit mesaj formatı: `[T<N>] <açıklama>`.
