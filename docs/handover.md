# Handover: v0s (status 2026-11-06)

Skrevet for den som tar over etter sesjonen som laget v0s. Kortversjon: v0s
bygger, testene går grønt lokalt, og en eldre versjon kjører i dev-nais. Siste
runde forenklinger er ikke committet eller rullet ut, og den maskinelle
sammenligningen mot v13s/Dependency-Track (DT) er neste store steg.

## Hva v0s er, og hvorfor

v0s skal erstatte både v13s og Dependency-Track for én tenant: lese teamenes
deklarerte workloads fra Nais API, hente attesterte CycloneDX-SBOM-er, matche dem
mot Trivy-databasen i prosessen og servere fakta over gRPC (`v0s.v1`). Det gjør
ingen vurderinger (ingen prioritet, risikoscore, trender eller historikk).
Begrunnelse og målinger: `docs/background/` (start med
`trivy-i-stedet-for-dt.html` og `trivy-db-vs-dt-analyse.md`). Domenespråk:
`CONTEXT.md`. Beslutninger: `docs/adr/0001-core-decisions.md`. Plan for
verifisering: `docs/verification.md`.

## Beslutninger tatt i sesjonen (ikke åpne igjen uten grunn)

- **Inventar** er deklarerte workloads (Application/Naisjob) fra Nais API, også
  skalert til null og jobber mellom kjøringer. Ikke Pods, ingen tilgang til
  tenant-cluster. `nais-system` er utenfor. Én image per workload; navnet er
  unikt per (environment, team).
- **Tags** slås opp til digest én gang og huskes så lenge tagen står i
  inventaret. Flytting av en mutable tag oppdages ikke før restart (dokumentert
  begrensning). Tags som ikke kan slås opp, vises som workload uten image med
  `resolve_error`.
- **Lesing er tenant-bred**: alle i tenanten ser alle teams funn. Teamfilter
  snevrer inn, det er ikke autorisasjon.
- **Ingen autentisering i v0s.** NetworkPolicy slipper bare inn `nais-system`;
  Nais API autoriserer brukere og aktør/team for suppressions.
- **Suppressions** er team-scopet, nøkkel `(team, image name, versjonsløs pakke,
  kanonisk sårbarhet)`, kun nåværende tilstand (set/delete), ingen utløpstid, ingen
  historikk (Nais API logger endringer). Tilstander: not_affected, false_positive,
  accepted_risk.
- **Funn** er workload-forekomster: ett funn per (workload, finding); suppression
  vurderes for workloadens team; tellinger er per forekomst.
- **Ufiksede funn vises** med fix-status (DT skjuler dem med `ignore_unfixed`).
- **Fjernet fra scope**: risikoscore og trend, topplister, trendgrafer, MTTR,
  image-nivå finding events, `first_seen_at`, VEX-justification, utløp.
- **Arbeidere**: sync, SBOM-henting og skanning serialiseres med PostgreSQL
  advisory locks på tvers av replikaer; bilder uten workload slettes straks etter
  sync; maks tre skanneforsøk per image per DB-versjon.
- **Trivy-DB** hentes fra GAR sin GitHub pull-through-cache
  (`europe-north1-docker.pkg.dev/nais-io/github-ptc/aquasecurity/trivy-db:2`), og
  digest logges.

## Repo-tilstand

- `~/ws/github.com/nais/v0s`, branch `main`, siste commit `b6e5285`.
  **Ingen remote**: `nais/v0s` finnes ikke på GitHub ennå (det er godkjent å
  opprette det som public repo og pushe).
- Ucommittede endringer (alle forenklinger siden `b6e5285`):
  - auth fjernet; leases erstattet av advisory locks; umiddelbar GC
  - `sboms`-tabellen slått inn i `images.sbom`; `finding_events` fjernet
  - suppressions som nåværende tilstand, team-scopet, uten utløp
  - funn som workload-forekomster
  - `Image.status` (`PENDING`/`SCANNED`/`NO_SBOM`/`FAILED`) + ett `error`-felt;
    `images.sbom_error`/`scan_error` slått sammen til `images.error`
  - `Workload.image_reference` og `resolve_error`; uoppløste workloads vises
  - tag-cache uten TTL og uten stale-digest-fallback
  - sesjonsmaterialet flyttet inn under `docs/background`, `docs/reviews`,
    `docs/archive` og `tools/compare`
- Siste verifisering (lokalt, før flyttingen): gofmt, `buf lint`, `go vet`,
  staticcheck og `go test -race ./...` mot PostgreSQL 18.6 gikk grønt, alle 10
  pakker.
- Migrasjonen `0001_schema.sql` er redigert på stedet (pre-1.0). En database som
  allerede har kjørt 0001, får ikke endringene; pilotbasen må nullstilles.

### Kjøre testene

Homebrew-Postgres mangler `postgres.bki`, og da hoppes database-testene stille
over. Bruk den frittstående PostgreSQL 18.6 i `~/.cache/v0s/pg18`;
`mise.local.toml` setter `V0S_PG_BIN`:

```sh
mise install
make generate
test -z "$(gofmt -l .)" && buf lint && go vet ./... && go tool staticcheck ./... && go test -race -count=1 ./...
```

Sjekk exit-status, ikke bare output.

## nais/api

- PR https://github.com/nais/api/pull/609 legger til internt gRPC
  `Workloads.ListImages` (deklarerte images per environment/team/workload;
  utelater `nais-system`; uautentisert bak eksisterende NetworkPolicy). Åpen,
  CI grønn, head `f367b8ee`, venter på review (Thomas har kommentert; svart).
- Worktree: `~/ws/github.com/nais/api-v0s-inventory`, branch
  `grpc-workload-images`.
- v0s har en vendret kopi av protoen i `third_party/naisapi`. Klient og server
  må rulles ut sammen: en feltnummer-mismatch dekodet tidligere stille til tomme
  images.

## dev-nais-piloten

- `dev-nais-management-v2`, namespace `nais-system`, manifest
  `deploy/dev-nais/management.yaml` (lagt på manuelt, ikke via Fasit).
  - v0s med én replika, kjører som KSA `v13s-sa`
  - CNPG-klusteret `v0s-db` (PostgreSQL 18, én instans, `dynamic-rwo`, uten
    backup, data kan bygges opp igjen)
- Kjørende v0s: `b6c6917`, digest `sha256:9c142984…`. Altså **ikke** dagens kode.
  Kjørende API-et har fortsatt Google-ID-token-auth og SBOM-state i stedet for
  status.
- Kjørende nais-api: egenbygd image `v0s-nais-api@sha256:cd119c0c…` (PR-commit
  `fd263e63` lagt over offisiell base). Byttes tilbake til offisielt image når
  PR #609 er merget og rullet ut.
- Lærdom fra utrullingen:
  - `standard-rwo` kan ikke festes på n4-nodene
  - Sigstore trenger skrivbar `HOME`
  - `nais-system` har default-deny egress, så hvert registry må åpnes eksplisitt
  - GAR-oppslag time-outet periodevis rett etter oppstart
  - `basseng/foo.baz` peker på en GAR-tag som gir 404
- Siste API-sjekk (etter reset 2026-11-05):
  - `ListWorkloads` ga 8 workloads, 4 med SBOM og 4 uten
  - `ListFindings` ga 3 UNKNOWN-funn på kafka-canary, de samme som lokal Trivy
    finner
- Tilgang: `nais login`, JITA til management-clusteret (manuelt, tidsbegrenset),
  port-forward til v0s :50051. Nåværende kode trenger ikke token; den kjørende
  versjonen trenger ID-token for `v13s-sa` med audience `v0s`.

## Neste steg

1. Commit endringene (foreslått: `Simplify v0s and expose image status for coverage`).
2. Opprett `nais/v0s` på GitHub og push (godkjent).
3. Bygg linux/amd64-image, publiser til GAR, oppdater digest i manifestet, vis
   diff, nullstill `v0s-db` og rull ut. Sjekk deretter at `ListWorkloads` gir
   status og uoppløste workloads, og at NetworkPolicy uten auth er så snever som
   tenkt.
4. Oppdater `tools/compare/compare.py` til nytt API: ingen token for v0s,
   `Image.status`/`error`, workload-forekomster, kanonisk advisory-gruppering, og
   join på digest. v13s bruker tag-identitet og har gamle `latest`-poster.
5. Kjør den maskinelle sammenligningen. Klassifiser hver critical/high-forskjell
   for hånd: v0s feil, v13s/DT feil, eller forsvarlig kildeforskjell. dev-nais har
   lite volum; nav (skyggekjøring, GCP først) trengs for skala og krever egen
   godkjenning.
6. Etter sammenligningen: gjennomgå skjema og funn-semantikk på nytt for flere
   forenklinger (brukeren ba om dette etter statusarbeidet).

## Åpne spørsmål og kjente risikoer

- Advisory-lock-arbeidere og umiddelbar sletting er testet lokalt
  (lås-eksklusjon, én skanner), men ikke under ekte replika-feil eller med to
  replikaer i drift.
- `SyncWorkloadImages` forutsetter at kallerne serialiserer (synk-låsen i
  reconcile); den har ingen egen lås.
- Uten auth hviler sikkerheten på NetworkPolicy. Alt i `nais-system` kan i dag
  nå både nais-api :3001 og v0s, og suppressions tar team og aktør fra
  kalleren.
- Console sine suppression-tilstander (in_triage, resolved, not_set …) har ikke
  noen avklart mapping til de tre i v0s.
- Status-hull:
  - API-et viser ikke hvilken Trivy-DB som er lastet, så funn som venter på ny
    skanning, kan ikke skilles fra ferske
  - `NO_SBOM` skiller ikke mellom manglende og forsinket attestering
  - retry etter `NO_SBOM` skjer først etter 6 t (kortere retry ble valgt bort
    foreløpig)
- Attestasjonsidentitet sjekker bare SAN (TODO i `internal/attest`). Samme
  svakhet som i v13s.
- Hvis en skanning varer lenger enn arbeidsløkken, finnes ingen fornyelse. Med
  advisory locks er dette en liveness-risiko, ikke en risiko for dobbel skanning.
- SBOM-dekning: kunde-SBOM-er uten OS-pakker og binærer utenfor pakkebehandler
  måles, men fikses ikke.
- Passordet i v13s sin `DATABASE_URL` ble skrevet ut i en tidligere
  terminalsesjon og bør roteres.

## Hva som ligger hvor

- `docs/background/`: v13s/DT-forklaring, suppression-spec for v13s (forkastet
  til fordel for v0s), Trivy-vs-DT-målinger og -analyse. Dette er bakgrunn og
  beskriver ikke dagens design.
- `docs/reviews/`: adversarial reviews runde 1 og 2 (begge fikset/lukket) og
  diffen fra simplify-reviewen 2026-11-05.
- `docs/archive/`: lane-prompter brukt til parallell implementering, og den
  opprinnelige nais/api-patchen (erstattet av PR #609).
- `tools/compare/`: sammenligningsskript og notater fra første dev-nais-pilot.
  Historisk; må oppdateres (se neste steg).
- Utenfor repoet: sesjonsmappa `~/ws/sessions/v13s-veien-videre/` har bare en
  klone av `console-frontend` igjen (brukt til Console-auditen). Den kan
  slettes eller klones på nytt.
