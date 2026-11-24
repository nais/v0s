# Dokumentasjon for v0s

Start med [repoets README](../README.md) for formål, avgrensning og utvikling.
Arkitektur og drift beskriver den implementerte tjenesten. Kontrakt- og
klientforslagene er beslutningsgrunnlag, ikke implementert Console/CLI eller
godkjenning av backendbytte.

| Dokument | Bruk det til |
|---|---|
| [Domenespråk](../CONTEXT.md) og [arkitektur](architecture.md) | Forstå dagens kode og avgrensning |
| [Drift](operations.md) | Bygge, rulle ut, oppgradere og feilsøke tjenesten |
| [Verifisering](verification.md) | Kontrollere funn, dekning, feilscenarioer og gjenoppretting før konsumentbytte |
| [Utviklerkontrakt](utviklerkontrakt.md) | Skille publiserte brukerløfter fra foreslått kontrakt og nødvendig migrering |
| [API, CLI og Console](api-cli-console-forslag.html) | Vurdere foreslått GraphQL, klientflyt og migreringsporter med syntetiske, klikkbare mocker |

Det implementerte API-et er definert i [protobuf-kontrakten](../proto/v0s/v1/v0s.proto).
HTML-forslaget kan åpnes direkte i nettleseren, uten server eller bygg.
Mockene sender ingen API-kall og kjører ingen kommandoer.

Dokumentasjonen er ikke en løpende utrullingsrapport. Historiske målinger og
grønne lokale tester erstatter ikke verifisering av aktuell versjon og tenant.
