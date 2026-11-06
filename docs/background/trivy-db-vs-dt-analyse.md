# Trivy DB i stedet for Dependency-Track? Utvidet sammenligning

Dato: 2026-10-29. Bygger på `trivy-vs-dt-maaling.md` (samme utvalg: 100 tilfeldige av 4111 aktive DT-prosjekter i nav).
Rådata/skript: `/tmp/dtm/` (`compare4.py`, `compare5.py`, `native.sh`).

Oppdatert 2026-10-29 med full native kjøring: images hentet fra GAR, Syft 1.55.0 → Grype 0.121.0
(DB bygget 2026-10-28) og `trivy image` 0.76.1, alt mot samme image-digest. 98 av 100 lyktes; 2 images
finnes ikke lenger i registryet.

## Kort svar

Ja, for vår bruk gir det mening. v13s trenger «SBOM inn, sårbarhetsfakta ut». Trivy DB gir det med færre
deler, og kildevalget gjøres av Aqua sitt Trivy-team i stedet for av oss. Vi er allerede avhengige av Trivy
(SBOM-generering i `nais/attest-sign`, og Trivy-analyzer inne i DT), så byttet innfører ingen ny tillitsrelasjon.
Det fjerner en.

Forbehold: vi mister noen få reelle funn og må selv hente EPSS. Se «Hva vi mister».

Etter native kjøring med Syft+Grype (seksjon 0): anbefalingen står. Grype er like god på critical/high
(98–99 %) og har EPSS/KEV innebygd. Men byttet krever ny SBOM-generering (Syft), og Grype gir mer støy.
Trivy bruker SBOM-ene vi allerede har. Grypes reelle fordel er runtime-binærer (Node, OpenJDK). Det hullet
har vi også i dag, og det bør løses i SBOM-genereringen, ikke ved å bytte matcher.

## 0. Native sammenligning: DT, Trivy og Syft+Grype (98 images)

DT-funn etter fjerning av Echo-/TuxCare-feilmatch og withdrawn-advisories, slått sammen på alias.
Matching på purl uten qualifiers; Go-versjon uten `v` og Debian-epoke normalisert.

| Severity | DT | Trivy (SBOM fra DT) | `trivy image` | Syft+Grype | Trivy ∪ Grype |
|---|---:|---:|---:|---:|---:|
| CRITICAL | 244 | 242 (99 %) | 242 (99 %) | 242 (99 %) | 242 (99 %) |
| HIGH | 1 477 | 1 458 (99 %) | 1 455 (99 %) | 1 441 (98 %) | 1 457 (99 %) |
| MEDIUM | 1 586 | 1 165 (73 %) | 1 165 (73 %) | 1 229 (77 %) | 1 244 (78 %) |
| LOW | 284 | 172 (61 %) | 172 (61 %) | 170 (60 %) | 172 (61 %) |
| UNASSIGNED | 569 | 70 (12 %) | 70 (12 %) | 107 (19 %) | 112 (20 %) |
| Funn totalt (rå) | | 4 207 | 4 417 | 5 155 | |

Funn som ikke finnes i DT:

| | Fikset, crit/high | Ufikset, crit/high | Lavere |
|---|---:|---:|---:|
| `trivy image` | 43 | 102 | 1 081 |
| Syft+Grype | 132 | 366 | 1 141 |

Trivy mot Grype på samme image: 225 av 242 Grype-critical og 1 902 av 2 015 Grype-high fant Trivy også;
171 av 173 Trivy-critical og 1 427 av 1 450 Trivy-high fant Grype også.

Funn:

1. **Trivy og Grype er like gode på det som betyr noe.** Begge fanger 98–99 % av DTs critical/high.
   Restene er de samme for begge: omstridte NVD-CVE-er (`async`, `jose`), TuxCare-støy og NVD/CPE-treff
   som `tomcat-embed-core` CVE-2026-29145. Grype mangler i tillegg 14, blant annet Alpine `zlib`
   ALPINE-CVE-2026-22184 og `guava` CVE-2026-102554.
2. **SBOM-en i attestasjonen er nok.** Trivy på SBOM fra DT og `trivy image` gir samme dekning. v13s trenger ikke
   hente images, bare SBOM-er vi allerede har.
3. **Grype finner sårbarheter i runtime-binærer som Trivy ikke ser.** Node.js (`/usr/local/bin/node`,
   5 images, f.eks. node 20.19.4 med flere HIGH), OpenJDK (2), Python og BusyBox installert utenom pakkebehandler.
   Det er reelle funn, og DT mangler dem også i dag fordi SBOM-en er laget av Trivy. Grype matcher dem via NVD/CPE.
4. **Grype har mer støy:**
   - `monorepo-symlink-test@0.0.0` merket som skadevare (critical) i 9 images. Det er en testfixture i
     `resolve/test/resolver/multirepo/package.json`.
   - 42 crit/high CPE-treff på Alpine-pakker uten fiksstatus (f.eks. `libssl3` CVE-2026-84782). Alpine secdb har
     dem ikke, så de er usikre.
   - Go stdlib rapporteres per binær, så Grype har flere rå funn.
5. **Grype gir EPSS (96 % av funnene) og KEV** direkte i resultatet. Med Trivy må v13s hente EPSS selv.

Drift, målt lokalt:

| | Trivy | Grype |
|---|---|---|
| DB, nedlasting | 130 MB (`trivy-db`); Java-DB (945 MB) trengs bare ved image-skanning, ikke for SBOM | 187 MB |
| DB, på disk | 1,5 GB | 3,1 GB |
| Bygges | hvert 6. time | daglig |
| 98 SBOM-er, 6 parallelle | 1,7 s | 37 s |
| SBOM-format | Trivy (dagens attestasjoner) | Syft; Trivy-SBOM gir dårlige OS-treff (se under) |

## 1. Første måling: SBOM eksportert fra DT (100 prosjekter)

DT-funn etter at åpenbar DT-støy er fjernet (Echo-/TuxCare-advisories matchet mot vanlige pakker, og
withdrawn-advisories), slått sammen på alias:

| Severity | DT | Trivy fant også | Grype fant også* |
|---|---:|---:|---:|
| CRITICAL | 288 | 282 (98 %) | 202 (70 %) |
| HIGH | 1 648 | 1 625 (99 %) | 1 304 (79 %) |
| MEDIUM | 1 731 | 1 300 (75 %) | 1 032 (60 %) |
| LOW | 308 | 194 (63 %) | 133 (43 %) |
| UNASSIGNED | 591 | 80 (14 %) | 41 (7 %) |

\* Grype er urettferdig målt her; se seksjon 0 for Syft+Grype: SBOM-ene våre er laget av Trivy, og kildepakkenavn (f.eks. `openssl` for `libssl3`)
ligger bare i `aquasecurity:trivy:SrcName`. Grype finner da ikke OS-funn som Alpine `libssl3` CVE-2025-9230.
Grype må testes mot SBOM fra Syft eller direkte mot image.

HIGH/CRITICAL i DT som Trivy ikke fant (29 av 1 936):
- Omstridte NVD-CVE-er uten pakkeadvisory: `async` CVE-2024-39249, `jose` CVE-2025-45767 (9 stk.).
- TuxCare-advisories på `fast-xml-parser` (3; støy som filteret ikke fanget).
- Reelle hull der GHSA har ufullstendig pakkeliste og DT fant via NVD/CPE: `tomcat-embed-core` CVE-2026-29145 (critical),
  `spring-boot-actuator-autoconfigure` CVE-2025-22235.
- `zod` GHSA-mrhx-c7xc-m3w5 (ikke forklart), noen RUSTSEC, `netty-transport-native-epoll` CVE-2026-42577.

Medium/low/unassigned som mangler i Trivy er i hovedsak ufiksede Chainguard/Wolfi-funn (`CGA-*`, ca. 1 000).
Trivy bruker Chainguard secdb, som bare lister fiksede sårbarheter.

Funn bare i Trivy: 1 304, hvorav 1 242 ufiksede (145 HIGH, 2 CRITICAL), nesten alle i Debian-pakker. DT skjuler
dem i dag fordi Trivy-analyzeren kjører med `ignore_unfixed: true`.

## 2. Kildehåndtering: hvem kuraterer?

| | Dependency-Track (slik vi kjører den) | Trivy DB |
|---|---|---|
| Hvem velger kilder | Vi: bootstrap-jobben slår på NVD-feeds, GitHub-mirroring (token), OSV (alle økosystemer), OSS Index, Trivy-analyzer | Aqua: `vuln-list-update` → `vuln-list` → `trivy-db` |
| OS-pakker | Blanding av OSV-distrodata, NVD/CPE og Trivy | Bare OS-leverandørens advisory (backport-bevisst); upstream-advisories kun med `--detection-priority comprehensive` |
| Språkpakker | GHSA + OSV + NVD/CPE + OSS Index | GHSA, Go vulndb, OSV (Rust), Node/Ruby/PHP-databaser; kommersiell bruk dokumentert per kilde |
| Severity | Per kilde; samme sårbarhet kan ha ulik severity under ulike ID-er | Leverandørens severity foretrekkes; `SeveritySource` og `VendorSeverity` i resultatet |
| Duplikater | Samme sårbarhet blir egne funn per ID (GHSA, CVE, CGA, ECHO …): 12 699 rå → 5 835 unike | Ett funn per pakke og sårbarhet |
| Kjente feil i vårt oppsett | 1 205 feilmatch fra Echo/TuxCare-økosystemer, 50 withdrawn | Ingen observert av samme type |

Echo/TuxCare-støyen kan fjernes ved å begrense `osv_ecosystems`. Men det viser poenget: med DT er vi selv
kildekuratorer, og feilkonfigurasjon blir til falske funn.

## 3. Driftsforskjell

### I dag (per tenant)

- DT backend (JVM, `requests` 4 Gi / 1 CPU, StatefulSet, PVC 10 Gi), frontend, egen Trivy-server (StatefulSet),
  Cloud SQL-instans med proxy, bootstrap-jobb, OIDC-klient, to ingresser og hemmeligheter (admin, GitHub-token, OSS Index).
- `nais/dependencytrack`: 85 commits i 2026, flere av dem driftstuning:
  - én replika fordi scheduleren dupliserte arbeid;
  - kadenser senket for å kutte Cloud SQL-egress fordi DT v4 skanner hele porteføljen hver time;
  - eksponert minnegrense;
  - GHSA→CVE-promotering for å unngå FK-feil.
- Egen Go-klient (`pkg/dependencytrack`, ~1,5 k håndskrevne linjer pluss generert klient).
- v13s: ~1,4 k linjer DT-spesifikk kode (`upload_attestation`, `finalize_attestation`, beslutningstabeller,
  `remove_from_source`, `sources/dependencytrack`, `updater`). Arbeidsflyten er last opp → vent på analyse →
  hent funn → synk suppression.
- Lesing er tregt: 37 s per 1 000 funn fra `/api/v1/finding`.
- DT v5 (sentral) ville løst scheduler- og skaleringsproblemene, men krever offline migrering. Kildekurateringen
  og v13s' opplastingsflyt blir værende.

### Med Trivy DB

- Én artefakt: `trivy-db:2` (130 MB komprimert, 1,6 GB på disk), bygget hvert 6. time og publisert til
  `mirror.gcr.io` og `ghcr.io`. `--db-repository` støtter vår egen speiling med fallback.
- Ingen database, JVM, UI eller analyzer-konfigurasjon. Matching skjer i v13s (bibliotek eller underprosess)
  eller mot én delt `trivy server`.
- Målt: 100 SBOM-er på 2,7 s (6 parallelle, laptop, DB i cache). Hele porteføljen (4 111) tar minutter, så
  full re-skann ved hver DB-oppdatering er billig.
- Ny jobb for v13s: lagre komponenter per image-digest, skanne nye SBOM-er, re-skanne aktive ved ny DB, og
  hente EPSS (FIRST, daglig CSV), som i dag kommer fra DT.
- Kan fjernes eller forenkles: DT-klient og opplastings-/polle-tilstandsmaskin, DT-write-back av suppressions,
  OSV-fetcher for fiksversjon (Trivy gir `FixedVersion` og `Status` per funn, backport-bevisst).
- Bonus: med komponentene lagret i v13s blir tenant-vid pakkesøk (Log4Shell-spørsmålet) mulig uten DT.
  Hvert funn kan merkes med `trivy-db UpdatedAt` som proveniens.

## 4. Risiko ved å lene seg på Trivy/Aqua

- **Én leverandør.** DB-en bygges av Aqua i GitHub Actions; koden er Apache-2.0. Prosjektet er mye brukt
  (GitLab speiler `trivy-db`; Harbor bruker Trivy som standard). Exit-vei: Grype DB (Anchore) har EPSS og
  KEV innebygd, men trenger SBOM med `upstream`-qualifiers (Syft), ikke Trivy-egenskaper.
- **Forsyningskjede-angrep mars 2026 (GHSA-69fq-xp46-6x23).** Trivy v0.69.4-binærer og -images, docker-tags
  0.69.5/0.69.6, `trivy-action` og `setup-trivy` ble kompromittert. DB-artefaktene er ikke nevnt som berørt.
  Vi bruker allerede Trivy (digest-pinnet i DT-chart, pinnet i `attest-sign`). Tiltak: pinn på digest, speil
  DB til GAR, verifiser signaturer, og alarmer på `UpdatedAt` eldre enn ~48 t.
- **Presisjon foran dekning** er Trivys uttalte valg. Det passer målet om mekaniske, troverdige fakta,
  men gir noen få falske negative der advisories er ufullstendige.
- Trivy som Go-bibliotek er ikke et stabilt offentlig API (ikke verifisert). Underprosess eller server er tryggere.
  Om `trivy server` støtter `sbom` er ikke verifisert.

## 5. Hva vi mister

| Tap | Omfang i utvalget | Vurdering |
|---|---|---|
| Ufiksede Chainguard/Wolfi-funn | ~1 000, ingen HIGH/CRITICAL utenom ~12 `CGA` | Ikke handlingsbare for team. Kan hentes fra OSV for Chainguard senere ved behov |
| NVD/CPE-treff | ~37 issues, få reelle (tomcat-embed-core, spring actuator) | Pris for presisjon. Kan delvis dekkes med `comprehensive` for språkpakker |
| EPSS per funn | Brukes i priority og høy-EPSS-telling | Må hentes fra FIRST (enkel daglig feed, som KEV-fetcheren) |
| DT UI, policies, VEX, notifications | Ikke i bruk | Ingen praktisk konsekvens |
| DTs historikk/metrics | – | v13s eier allerede historikk |
| (Ikke dekket i dag heller) Runtime-binærer utenom pakkebehandler | Node i 5, OpenJDK i 2 av 98 images | Grype finner dem via NVD/CPE. Kan løses ved å berike SBOM-en (f.eks. Syft-binærdeteksjon i `attest-sign`) |

## 6. Beslutninger før bytte

1. Ufiksede funn: vise (Trivy-standard) eller skjule (`--ignore-unfixed`, som i dag)? Anbefaling: lagre
   `Status`, filtrer i API-et.
2. Kjøremodus: underprosess i v13s-worker med delt DB-volum eller én `trivy server`.
3. Verifiser på et større, stratifisert utvalg (Java/Node/Go, Debian/Alpine/Chainguard/distroless).
   Native image-skanning på 98 images er gjort; Trivy på SBOM og Trivy på image ga samme dekning.
4. Parallellkjøring: v13s skriver Trivy-funn ved siden av DT i en periode og sammenligner per workload
   før DT slås av.
5. Runtime-binærer: skal `attest-sign` berike SBOM-en med binærer (Node, JDK, Python) installert utenom
   pakkebehandler?

## Forbehold

- 100 av 4111 prosjekter (98 i den native kjøringen). Seksjon 1 bruker SBOM eksportert fra DT;
  seksjon 0 bruker images fra GAR.
- Grype-tallene i seksjon 1 sier mer om SBOM-formatet enn om Grype DB. Seksjon 0 er den rettferdige
  Grype-målingen.
- Drifts-tall er fra kode, konfig og commit-historikk; ingen kostnads- eller ressursmåling fra klyngen.
