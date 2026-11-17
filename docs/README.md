# v0s: forklaring, kontrakt og beslutningsgrunnlag

Start med [den visuelle pitchen](pitch.html). Den er én selvstendig HTML-fil:
åpne den direkte i nettleseren, uten server, bygg eller nettverk.
Målgruppen er Nais-teamet; materialet er til diskusjon, ikke en cutover-godkjenning.

| Dokument | Bruk det til |
|---|---|
| [Pitch](pitch.html) | Forklare verdien, flyten og hva som gjenstår |
| [API, CLI og Console](api-cli-console-forslag.html) | Prøve Console- og CLI-mocker med samme eksempeldata; nytt API, kutt og arbeid per repo (2026-11-16) |
| [Utviklerkontrakt](utviklerkontrakt.md) | Skille dagens løfter fra foreslått kontrakt og nødvendig migrering |
| [Status 2026-11-10](status-2026-11-10.md) | Se samlet arbeid, ressursreservasjoner, daterte målinger, kataloggap og neste steg |
| [Domenespråk](../CONTEXT.md) og [arkitektur](architecture.md) | Forstå dagens kode og avgrensning |
| [Drift](operations.md) og [verifisering](verification.md) | Bygge, rulle ut og kontrollere tjenesten |
| [Arkiv](archive/README.md) | Lese tidligere forslag, reviews og pilotresultater som historikk |

## Samlet fra sesjoner, uten å importere produksjonsdata

Dette repoet er nå hjemmet for den kuraterte forklaringen, kontraktforslaget og
arbeidslisten. Koden for identity, database, nettverk og ytelse var allerede
samlet i base-repoet før denne dokumentasjonsendringen.

Materialet nedenfor ble gjennomgått fra
`~/ws/sessions/v0s-runtime-identity/` 2026-11-10. Nyere resultater har forrang
over eldre handovere; motstridende status er ikke kopiert videre som gjeldende.

| Sesjonskilde | Bevart her |
|---|---|
| `UTVIKLERKONTRAKT.md` | [Utviklerkontrakt](utviklerkontrakt.md), kontrollert mot publisert dokumentasjon |
| `README.md`, `cnpg-result-2026-11-09.md`, `dns-platform-result-2026-11-09.md`, `netpol-chart-result-2026-11-09.md`, `nav-result-2026-11-09.md` | Arbeid og utrullingsobservasjoner i [status](status-2026-11-10.md) |
| `latency/RESULT.md`, `HANDOVER_LATENCY.md` | Implementert ytelsesarbeid, målemetode og live-begrensninger i status |
| `analysis-findings-2026-11-10/FRESH_REPORT.md`, `NEXT_TASKS.md` | Nyeste aggregerte sammenligning, kildegap og prioriterte gater i status |
| `analysis-nav/` og eldre delrapporter | Historisk grunnlag, erstattet av det ferske uttaket der tallene avviker |

Etter brukerens avklaring inngår aggregerte NAV-målinger, navngitte kataloggap
og en datert sammenligning av ressursreservasjoner.
Rå API-uttrekk, workload-/image-lister, logger, interne ressursidentifikatorer,
credentials og originale private analyser er **ikke** importert. De lokale
originalene er urørt. Dette er ikke et flytte-/sletteoppdrag for sesjonsmapper
eller worktrees. Den opprinnelige funksjons- og funnsammenligningen er ikke
kjørt på nytt; ressursreservasjonene har en separat read-only-avlesning
2026-11-10.

De eldre v13s/DT-undersøkelsene var allerede samlet i
[bakgrunnsarkivet](archive/background/README.md).
