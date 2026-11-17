# v13s og veien videre

Bakgrunnsmateriale fra sesjonen som førte til v0s (oktober 2026), flyttet hit fra
`~/ws/sessions/v13s-veien-videre/`. Nyere samlet status og kilder finnes i
[dokumentasjonsoversikten](../../README.md).
Stiene under var relative til sesjonsmappa; review-mappene ligger nå i
[`../reviews/`](../reviews/).

Status da: forklaring og forslag til teamdiskusjon. Ingen kodeendringer.

- `v13s-forklaring.html` – interaktiv forklaring av modell, API, suppressions og forslag (v13s + d14k v5).
- `suppression-spec.md` – spec for varige suppressions i v13s (v1: image + pakke uten versjon + kanonisk CVE, utløp, historikk, batch, ingen DT-skriving).
- `trivy-vs-dt-maaling.md` – måling i nav (100 prosjekter): Trivy alene dekker ~97–98 % av DTs high/critical; differansen er mest DT-støy, men ufiksede Chainguard-funn og enkelte NVD/CPE-treff går tapt.
- `trivy-db-vs-dt-analyse.md` – utvidet sammenligning (dekning inkl. Grype, kildekuratering, drift, risiko, hva vi mister); anbefaling: Trivy DB direkte i v13s, med EPSS-feed og parallellkjøring før DT fjernes.
- `trivy-i-stedet-for-dt.html` – Slack-vennlig oppsummering (selvstendig HTML): native måling Trivy/Grype/DT på 98 images, og anbefaling per tenant med sentralt speil av trivy-db.
- Grunnlag: nais/v13s main (1dadf12, 1 bak origin), nais/api main, Dependency-Track v5-dokumentasjon (GA juni 2026).

Åpne spørsmål: tenant-isolasjon i sentral DT v5, authz og ytelse for vulnerability policies, hva Console bruker i stedet for priority.

## v0s (lokal repo `~/ws/github.com/nais/v0s`)

- Adversarial reviews: runde 1 (`v0s-review-1/`) fikset; runde 2 (`v0s-review-2/`) ingen blokkere, tre av fem lave funn fikset.
- Utsatt med vilje: attestasjonsidentitet sjekker bare SAN. For gjenbrukbare workflows er SAN den kalte workflowen, så et repo utenfor nais/navikt som kaller en offentlig gjenbrukbar workflow der, matcher. Vurder å også kreve source-repository-owner-utvidelsen i sertifikatet (TODO i `internal/attest/attest.go`). v13s har samme sjekk.
- Gjenstår: skanner som krasjer prosessen (OOM) blir krevd på nytt hvert 5. min (forslag: tell forsøk per image); komponentlister for allerede skannede images oppdateres ikke ved ny skanning (irrelevant før deploy).
