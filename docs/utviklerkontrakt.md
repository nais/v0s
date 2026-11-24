# Utviklerkontrakt for sårbarhetsoversikten

**Forslag til teamdiskusjon, opprinnelig datert 2026-11-10.** Ikke en publisert
kontrakt, implementert Console-opplevelse eller godkjenning av backendbytte.

Det viktige skillet er mellom **hva Nais tilbyr teamene**, og **hvordan vi
produserer informasjonen**. Teamene skal ikke måtte forstå scanner-riggen for å
bruke oversikten. Et enklere internt system gir oss ikke lov til å endre
brukerløftet i det stille.

## Dagens dokumentasjon er allerede en kontrakt

Disse sidene ble kontrollert på nytt 2026-11-10:

- [Oversikten](https://docs.nais.io/services/vulnerabilities/) ber teamene
  generere SBOM og attestasjoner og bruke Console til å håndtere sårbarheter.
- [Referansen](https://docs.nais.io/services/vulnerabilities/reference/)
  beskriver begrenset avhengighetsgraf og egne Maven-/Gradle-SBOM-er. Formuleringen
  om at DTs Trivy-integrasjon sikrer deteksjon fra containeren bør nyanseres:
  ingen av løsningene gir generell fullstendighetsgaranti.
- [Varslingsguiden](https://docs.nais.io/services/vulnerabilities/how-to/alert-on-vulnerabilities/)
  dokumenterer severity, KEV, prioriteringsklasser, risikoscore og at undertrykte
  funn ikke telles. Den beskriver også forsinkelse før metrikker oppdateres.

Team kan allerede ha varsler basert på disse metrikkene og betydningen deres.
At v0s ikke beregner prioritet og risikoscore, betyr derfor **ikke** at Nais
automatisk kan fjerne dem. Videreføring i konsumentlaget eller varslet avvikling
må være et eksplisitt produktvalg.

## Foreslått tekst til teamene

### Hva sårbarhetsoversikten viser

Nais viser kjente sårbarhetstreff for pakkene i den attesterte SBOM-en til imaget
som er registrert for applikasjonen eller jobben din. Treffene beregnes med
Trivys sårbarhetsdatabase og kildepolicy. Lagrede SBOM-er analyseres på nytt når
databasen oppdateres.

For OS-pakker følger vi normalt distribusjonens sikkerhetsinformasjon, slik at
backportede sikkerhetsfikser tas hensyn til. For språkpakker brukes Trivys
støttede økosystemkilder. Alvorlighetsgrad og tilgjengelig fiks kommer fra
kildene og kan endre seg.

Et treff betyr at pakken og versjonen er registrert som berørt. Det betyr ikke
nødvendigvis at den sårbare funksjonen brukes, eller at applikasjonen kan
utnyttes. EPSS og CISA KEV gir supplerende informasjon, ikke bevis for
utnyttbarhet i din applikasjon.

**Ingen funn er ikke en garanti for at imaget er uten sårbarheter.** Pakker som
mangler i SBOM-en, manglende advisories og forsinkelser i datakildene kan gi
manglende treff. Manglende SBOM eller mislykket analyse skal skilles fra en
vellykket analyse uten funn. En signatur bekrefter ikke at pakkeinventaret er
komplett.

Teamet er ansvarlig for å levere en dekkende SBOM, vurdere relevante treff og
oppdatere eller dokumentere vurderingen sin. Nais er ansvarlig for innhenting,
analyse, oppdatering og synliggjøring av dekningsproblemer.

## Ansvar og avgrensning må være synlig

| Teamene gjør | Nais gjør | Vi lover ikke |
|---|---|---|
| Leverer attestert SBOM og deployer nytt image ved endring | Knytter deklarert workload til image-digest og verifiserer attestasjonen | At signert SBOM inneholder alle pakker eller runtime-binærer |
| Vurderer treff i sin brukskontekst og oppdaterer eller begrunner vurderingen | Viser kilde, alvorlighet, fiks, EPSS/KEV og dekningsproblemer | At et pakketreff beviser utnyttbarhet, eller at null treff beviser trygghet |
| Forholder seg til dokumenterte varsler og endringer | Oppdaterer funn og drifter innhenting, databaser og gjenoppretting | Umiddelbar scanning eller en oppdateringsfrist som ikke er besluttet og målt |

v0s behandler applikasjoner og jobber slik Nais API deklarerer dem, også
applikasjoner skalert til null og jobber mellom kjøringer. Plattformworkloads
og injiserte sidecars er utenfor. En flyttet mutable tag spores ikke; deploy
en ny tag eller digest for å endre imaget.

API-et har dekningsstatusene `PENDING`, `SCANNED`, `NO_SBOM` og `FAILED`,
pluss uavklarte image-referanser. `SCANNED` betyr at en analyse er fullført,
ikke at alt er dekket. En mislykket rescan kan beholde forrige funn og
`SCANNED` med en feil. Console må formidle dette, ikke bare vise et grønt nulltall.

Klientene bruker tjenestens nåværende bilde. Det finnes ingen klientstyrt
freshness-protokoll eller avtalt ende-til-ende-frist. Oppdatering og stans i
arbeidsløkkene er Nais sitt driftsansvar; loop-intervaller er ikke et SLA.

## Teamets vurdering skal overleve neste bygg

En suppression gjelder `(team, miljø, workload-navn, image-navn, versjonsløs
pakke, kanonisk sårbarhets-ID)`. Den overlever nye image-/pakkeversjoner for den
workloaden, men ikke et bytte av image-repository. Andre apper, jobber og miljøer
arver ikke vurderingen, selv om de har samme team og image.
Tilstandene er `NOT_AFFECTED`, `FALSE_POSITIVE` og `ACCEPTED_RISK`.

API/Console kan liste andre berørte workloads med `ListFindings`, filtrert på
sårbarhets-ID/alias og eventuelt pakke. Bruk `suppressed=INCLUDE` for å få med
allerede vurderte funn. `CountFindings` gruppert per workload kan brukes når det
bare trengs identiteter og antall. Brukeren velger hvilke workloads som skal få
samme vurdering; `SetSuppressions` skriver en egen vurdering per nøkkel i én
atomisk batch innen samme autoriserte team. Dette er ikke automatisk arv eller
en ferdig implementert Console-funksjon.

v0s lagrer nåværende vurdering, begrunnelse og aktør, ikke utløp eller historikk.
Konsumenten må autorisere skriving og eventuelt føre aktivitetslogg.
Vurderingene er varige data: de kan ikke bygges opp igjen fra registry og Trivy.
Backup og bevist restore er derfor en del av Nais sitt ansvar.

Lesing i v0s er tenant-bred; et teamfilter er ikke tilgangskontroll.
Selve gRPC-API-et har ikke autentisering og stoler på tillatte konsumenter
bak NetworkPolicy. Autorisasjon av brukerhandlinger må ligge i konsumentlaget;
team og aktør fra en tillatt kallende tjeneste er ikke uavhengig verifisert av v0s.

## Kildeavgrensninger

Scannerbyttet er også et valg av kildepolicy. En katalog kan mangle advisories
for berørte språkpakker eller utelate vendor-records som ennå ikke har en fiks.
Samtidig kan en bredere kilde gi feil pakketilskrivning, tilbaketrukne advisories
eller treff utenfor berørte versjoner. Flere funnrader betyr ikke bedre dekning.

Skill mellom mangler i den opprinnelige SBOM-en, manglende kildeoppføringer,
bevisst kildeavgrensning og konkrete matcherfeil. Minimale komponenteksempler
mot pinnede scanner-/DB-versjoner kan isolere årsaken, men erstatter ikke
verifisering av originale SBOM-er eller vurdering av faktisk utnyttbarhet.
Overlapp mellom to systemer er ikke målt recall eller en korrekthetsprosent.
Se [verifiseringsmetoden](verification.md#findings-and-coverage).

## Før dette kan bli det publiserte løftet

1. **Avklar kildekontrakten.** Aksepter og dokumenter konkrete Trivy-begrensninger,
   eller krev avgrenset supplerende/upstream-dekning. Følg opp minimale
   reproduksjoner hos datakilden fremfor å hardkode advisory-spesialtilfeller.
2. **Vis dekning i Console.** Manglende SBOM, feil og tidligere beholdte funn må
   skilles fra vellykket analyse uten treff. Dette er et integrasjonskrav,
   ikke noe denne dokumentasjonen implementerer.
3. **Bevar eller avvikle varsler eksplisitt.** Dokumenter videre skjebne for
   `nais_workload_vulnerabilities`, `nais_workload_vulnerabilities_kev`,
   `nais_workload_vulnerabilities_priority` og `nais_workload_risk_score`,
   inkludert telle-/suppression-semantikk og oppdateringsforsinkelse.
4. **Migrer vurderinger bevisst.** Ikke gjør `IN_TRIAGE`, `RESOLVED` eller
   `NOT_SET` om til `ACCEPTED_RISK` automatisk. Bevar team, image-/pakkeomfang,
   aliaser og begrunnelse; verifiser restore før overgangen.

Publiser sluttresultatet på de eksisterende oversikts-, referanse- og
varslingssidene, med endringsvarsel ved brudd. Dette repo-dokumentet er
beslutningsgrunnlaget, ikke en konkurrerende offentlig sannhetskilde.

Teknisk fasit for det implementerte API-et:
[protobuf](../proto/v0s/v1/v0s.proto), [domenespråk](../CONTEXT.md) og
[arkitektur](architecture.md).
