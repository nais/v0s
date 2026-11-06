# Måling: Trivy alene vs. dagens Dependency-Track (tenant nav)

Dato: 2026-10-29. Kun lese-kall mot `dependencytrack-backend.nav.cloud.nais.io` (DT 4.14.6).
Rådata og skript: `/tmp/dtm/` (flyktig).

## Metode

- 4111 aktive DT-prosjekter (730 014 funn inkl. suppressed). Tilfeldig utvalg 100 prosjekter (seed 42).
- DT-funn: `GET /api/v1/finding/project/{uuid}?suppressed=true`.
- SBOM: DT-eksport `GET /api/v1/bom/cyclonedx/project/{uuid}?variant=inventory` → `trivy sbom` 0.76.1,
  DB oppdatert 2026-10-29, *uten* `--ignore-unfixed`.
- Matching per (purl uten qualifiers, sårbarhet). DT-funn slått sammen når de deler ID/alias;
  aliaser/`upstream` for OSV-ID-er (GO, CGA, ECHO, CLSA, RUSTSEC, BIT …) slått opp i api.osv.dev;
  `DEBIAN-/ALPINE-CVE-x` → `CVE-x`; GHSA-ID-er hentet fra Trivy-referanser.

## Resultat (100 prosjekter)

| | DT | Trivy fant også |
|---|---:|---:|
| Rå funn | 12 699 | – |
| Unike issues etter alias-sammenslåing | 5 835 | 3 495 |
| CRITICAL | 288 | 282 (98 %) |
| HIGH | 1 673 | 1 625 (97 %) |
| MEDIUM | 1 755 | 1 302 |
| LOW | 311 | 194 |
| UNASSIGNED | 1 808 | 92 |

Trivy rå funn: 4 804, hvorav 1 297 ikke finnes i DT.

### Kun i DT (2 340 issues)

| Kategori | Antall | Vurdering |
|---|---:|---|
| Echo/TuxCare-advisories (`ECHO-*`, `CLSA-*`, økosystem `Echo:*`/`TuxCare:*`) matchet mot vanlige maven/npm/go-pakker | 1 205 | Falske positiver i DT |
| Trukket tilbake (withdrawn) GHSA/OSV | 50 | Falske positiver i DT |
| Kun NVD/CPE-match | 37 | Mest støy (f.eks. openssl/perl i Debian der Debian har backportet fiks); enkelte reelle (spring-boot-actuator-autoconfigure CVE-2025-22235) |
| Chainguard/Wolfi `CGA-*` uten fiks (`introduced: 0`, ingen `fixed`) | ~1 000 (rundt halvparten UNASSIGNED) | Reelle, men ufiksede; Trivy rapporterer bare fiksede for Chainguard/Wolfi |
| Annet | ~50 | Se under |

Reelle HIGH/CRITICAL som Trivy ikke fant (i utvalget):
- `tomcat-embed-core` CVE-2026-29145 (critical): GHSA lister bare `org.apache.tomcat:tomcat`; DT fant via NVD/CPE.
- `zod` GHSA-mrhx-c7xc-m3w5 (high): ikke i Trivy-resultatet; årsak ikke undersøkt (DB-etterslep?).
- Noen RUSTSEC uten CVE, `netty-transport-native-epoll` CVE-2026-42577.
- `bitnami/redis` BIT-REDIS-*: ikke undersøkt; kan skyldes SBOM-eksport fra DT.

### Kun i Trivy (1 297 funn)

Nesten alt er Debian-pakker uten fiks (`affected` 1 135, `fix_deferred` 82, `will_not_fix` 25), hvorav 138 HIGH.
Dagens DT skjuler disse fordi Trivy-analyzeren kjører med `ignore_unfixed: true`.

## Konklusjon

- Trivy dekker ~97–98 % av DTs HIGH/CRITICAL. Mesteparten av differansen er støy i DT
  (Echo/TuxCare-feilmatch, withdrawn, NVD/CPE).
- Reelle tap: ufiksede Chainguard/Wolfi-sårbarheter og enkelte NVD/CPE-treff der GHSA har ufullstendige pakkenavn.
- Trivy uten `ignore-unfixed` gir flere ufiksede Debian-funn; må velges bevisst.

## Forbehold

- Utvalg 100 av 4111 prosjekter; ikke stratifisert.
- SBOM eksportert fra DT, ikke original attestasjon.
- DT `attribution` viser kun første analyzer; derfor sammenlignet mot faktisk Trivy-kjøring.
- Ingen manuell verifisering av hvert gjenværende funn.
