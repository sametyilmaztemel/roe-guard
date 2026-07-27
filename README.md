# roe-guard

**Rules of Engagement policy-enforcement library — scope, gate, log, clean.**

`roe-guard` is a lightweight, open-source Python library that lets security
operators define, programmatically, *what* an operation may touch — which
targets, which time-windows, which action types — and automatically blocks
(logs) every out-of-scope action.

It is the open-source reference implementation of 0rce Labs'
*zero-unauthorized-operations* principle: **scoped, gated, logged, cleaned.**

---

## Kurulum

### Gereksinimler

- Python >= 3.10

### Kaynaktan kurulum (geliştirme)

```bash
git clone https://github.com/orce-labs/roe-guard.git
cd roe-guard
pip install -e ".[dev]"
```

### PyPI (yayınlandığında)

```bash
pip install roe-guard
```

### Doğrulama

```bash
roe-guard --version
roe-guard --help
```

---

## Varsayımlar

> **Not:** Bu bolum, T1 (repo iskeleti) asamasinda yapilan varsayimlari
> listeler. Spekte acikca belirtilmeyen kararlar burada belgelenmistir.

1. **PyPI paket adi:** `roe-guard` musait oldugu varsayilmistir (spec 12'de
   acik karar olarak isaretliydi). Musait degilse paket adi T9 oncesi
   guncellenecektir.

2. **GitHub organizasyonu:** Repolar `orce-labs` organizasyonu altinda
   toplanacagi varsayilmistir (`github.com/orce-labs/roe-guard`). Organizasyon
   henuzu kurulmadiysa URL guncellenecektir.

3. **Build backend:** `setuptools` secilmistir (stdlib ile gelen en stabil
   secenek; `flit` / `hatchling` yerine). Tek dosya `pyproject.toml` yeterli.

4. **CLI framework:** Harici bir bagimlilik (`click`, `typer`) eklemek yerine
   stdlib `argparse` kullanilmistir — spec'in "sifira yakin bagimlilik"
   ilkesine uygun.

5. **Tip imzalari:** Modullerdeki fonksiyon imzalari spekteki API tasarimina
   (6) sadik kalir sekilde yazilmistir; implementation T2-T7'de gelecektir.

6. **Marka adi:** README ve LICENSE'ta "0rce Labs" kullanilmistir.

---

## Gelistirme

```bash
# Testleri calistir
pytest

# Lint
ruff check roe_guard/
```

## Lisans

MIT — bkz. [LICENSE](LICENSE).

---

> **NOT (Branch Koruması):** `main` branch'ine doğrudan push kapatılmalıdır.
> Tüm değişiklikler `ticket/T<N>-<slug>` formatında branch + Pull Request
> üzerinden merge edilmelidir. Bu ayar GitHub repo settings → Branches →
> Branch protection rules → `main` → "Require a pull request before merging"
> üzerinden manuel yapılmalıdır. Commit mesaj formatı: `[T<N>] <açıklama>`.
