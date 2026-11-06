# Spec: Varige suppressions i v13s (v1, pragmatisk)

Status: utkast · Repo: nais/v13s (+ nais/api) · Grunnlag: main (v13s 1dadf12, api main)

## Problem

En suppression lagres i dag i `suppressed_vulnerabilities` med nøkkelen
`(image_name, package, cve_id)`. `package` er DT-komponentens purl **med versjon**.
Det gir disse problemene:

1. **Suppressionen forsvinner når pakken oppgraderes.** Bumper teamet `snakeyaml@1.33 → @1.34` og CVE-en fortsatt gjelder, dukker funnet opp igjen.
2. **Ingen utløp og ingen historikk.** Bare siste tilstand lagres. `suppressed_by` er fritekst, og historikken finnes kun i activity log i nais api.
3. **Én og én.** `SuppressVulnerability` tar ett finding-id. Det finnes ingen batch og ingen liste over suppressions.
4. **Synk begge veier mot DT.** Updateren sammenligner og pusher analysis til hvert DT-prosjekt (image:tag) hver 4. time (`updater/source.go`, `sources/dependencytrack.go`). Det gir mye kompleksitet for et resultat ingen leser, fordi v13s selv er fasit.
5. **Alias-rader.** Det skrives én rad per kanonisk CVE + alle aliaser. I tillegg kjører en rekey-cron, fordi én spørring (`ListVulnerabilitiesForImage`, `vulnerabilities.sql:535`) joiner på rå `v.cve_id`.

## Mål

- En suppression gjelder for **image_name + pakke (uten versjon) + kanonisk CVE**. Den overlever både ny tag og ny pakkeversjon.
- Valgfri **utløpsdato**. Etter utløp er funnet aktivt igjen uten manuelt arbeid.
- **Historikk** ved at rader bare legges til: en endring er tilbaketrekking av den gamle raden pluss en ny rad.
- Valgfri **VEX-justification** i tillegg til dagens state.
- **Batch-opprettelse med dry run**, tilbaketrekking og listing, slik at Console og agenter (MCP) kan jobbe effektivt.
- **v13s er eneste fasit. Vi slutter å skrive suppressions til DT.**

## Ikke-mål (v1)

- Scope på team- eller tenantnivå. Summary beregnes per image, og et image kan brukes av flere team, så det krever en egen modell.
- Versjonsområder (`vers:maven/<2.0`). Matching per økosystem er ikke trivielt. Pakke uten versjon dekker hovedbehovet.
- DT v5 policies, flyt med «foreslått → godkjent» og varsler før utløp.
- Endringer i priority/risk_score. Det er en separat sak.

## Modell

```sql
CREATE FUNCTION purl_without_version(p TEXT) RETURNS TEXT
    LANGUAGE SQL IMMUTABLE PARALLEL SAFE
    RETURN regexp_replace(regexp_replace(p, '[?#].*$', ''), '@[^/@]*$', '');
-- pkg:maven/org.yaml/snakeyaml@1.33                    -> pkg:maven/org.yaml/snakeyaml
-- pkg:npm/@babel/core@7.24.0                           -> pkg:npm/@babel/core
-- pkg:npm/%40babel/core@7.24.0                         -> pkg:npm/%40babel/core
-- pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64   -> pkg:deb/debian/openssl
-- pkg:golang/github.com/foo/bar@v1.2.3                 -> pkg:golang/github.com/foo/bar
-- pkg:npm/@babel/core (uten versjon)                   -> uendret

ALTER TABLE vulnerabilities
    ADD COLUMN package_name TEXT GENERATED ALWAYS AS (purl_without_version(package)) STORED;
CREATE INDEX ON vulnerabilities (image_name, package_name);

CREATE TYPE vex_justification AS ENUM (
    'code_not_present', 'code_not_reachable', 'requires_configuration',
    'requires_dependency', 'requires_environment', 'protected_by_compiler',
    'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control'
);

CREATE TABLE vulnerability_suppressions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_name      TEXT NOT NULL,
    package_name    TEXT NOT NULL,          -- purl uten versjon/qualifiers
    cve_id          TEXT NOT NULL,          -- alltid kanonisk ID
    state           vulnerability_suppress_reason NOT NULL,  -- gjenbruk av eksisterende enum, ikke 'not_set'
    justification   vex_justification,      -- valgfri
    reason_text     TEXT NOT NULL,
    created_by      TEXT NOT NULL,          -- identitet fra nais api (bruker eller SA)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,            -- NULL = utløper ikke
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT,
    expiry_applied_at TIMESTAMPTZ,          -- intern: utløp er reflektert i summaries
    CHECK (state <> 'not_set'),
    CHECK (expires_at IS NULL OR expires_at > created_at)
);
-- Maks én ikke-trukket rad per nøkkel. Historikken er rader med revoked_at satt.
CREATE UNIQUE INDEX ON vulnerability_suppressions (image_name, package_name, cve_id)
    WHERE revoked_at IS NULL;
```

**Aktiv suppression** = `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`.

**Matching** mot findings, på samme form på alle join-steder:

```sql
LEFT JOIN vulnerability_suppressions s
    ON s.image_name = v.image_name
   AND s.package_name = v.package_name
   AND s.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
   AND s.revoked_at IS NULL
   AND (s.expires_at IS NULL OR s.expires_at > now())
```

Join-stedene som må endres: 5 i `queries/vulnerabilities.sql` (inkl. linje 535, som går over til kanonisk ID), 1 i `queries/cve_summary.sql`, og materialized views fra 0041/0042, som må gjenskapes i migrasjonen.

## Oppførsel

- **Opprett**:
  1. Slå opp kanonisk CVE.
  2. Trekk tilbake en eventuell eksisterende ikke-trukket rad for nøkkelen, med `revoked_by` = ny `created_by`. Dette gjelder også rader som allerede har utløpt.
  3. Sett inn ny rad.
  4. Regn ut summary på nytt for alle tags av `image_name` som har workloads.

  Alt skjer i én transaksjon.
- **Trekk tilbake**: sett `revoked_at`/`revoked_by` og regn ut summaries på nytt.
- **Utløp**: en cron hver time finner rader med `expires_at <= now()` og `expiry_applied_at IS NULL`, regner ut summaries for berørte images på nytt og setter `expiry_applied_at`. MV-ene plukker det opp ved neste refresh.
- **Nye tags og nye pakkeversjoner** matcher automatisk via `package_name`. Det trengs ingen kopiering.
- **Aliaser**: lagres kun kanonisk. `RekeySuppressedAliasesToCanonical` og alias-utvidelsen i `suppressionWorkflow` fjernes. Får en CVE et nytt alias senere, matcher joinen fortsatt via `cve_alias`.
- **DT**: `MaintainSuppressedVulnerabilities`, `ListSuppressedVulnerabilitiesForImage` og sammenligningen i `fetchVulnerabilityData` fjernes. Analyser som allerede ligger i DT, blir liggende. De er ufarlige, fordi updateren henter med `includeSuppressed=true` og ignorerer DT-flagget.

## API (gRPC, kun tillegg)

```proto
message Suppression {                       // eksisterende melding, nye felt
  bool suppressed = 1;
  SuppressState suppressed_reason = 2;
  string suppressed_by = 3;
  string suppressed_details = 4;
  google.protobuf.Timestamp last_updated = 5;
  string id = 6;
  optional VexJustification justification = 7;
  optional google.protobuf.Timestamp expires_at = 8;
}

message SuppressionSpec {
  string image_name = 1;
  string package = 2;                       // purl, versjon strippes av serveren
  string cve_id = 3;                        // CVE eller alias
  SuppressState state = 4;                  // NOT_SET avvises
  optional VexJustification justification = 5;
  string reason = 6;                        // påkrevd
  optional google.protobuf.Timestamp expires_at = 7;
}

rpc CreateSuppressions(CreateSuppressionsRequest) returns (CreateSuppressionsResponse);
// request:  repeated SuppressionSpec items (maks 500); string created_by; bool dry_run
// response: per item { Suppression (tom ved dry_run), int32 matched_findings,
//                      repeated string matched_image_tags, optional string error }
// Alt eller ingenting: én ugyldig item gir INVALID_ARGUMENT med feil per item.

rpc RevokeSuppressions(RevokeSuppressionsRequest) returns (RevokeSuppressionsResponse);
// request: repeated string ids; string revoked_by

rpc ListSuppressions(ListSuppressionsRequest) returns (ListSuppressionsResponse);
// filter: image_names[], cve_id, package, status (ACTIVE|EXPIRED|REVOKED), expires_before;
// paginering som i resten av APIet
```

`SuppressVulnerability` beholdes for Console. Den slår opp findingen og kaller samme logikk med én spec (`suppress=false` betyr trekk tilbake aktiv rad). **Endringen i oppførsel er bevisst**: den gjelder nå alle versjoner av pakken i dette imaget.

## nais api

- `UpdateImageVulnerabilityInput` får valgfrie felt `justification` og `expiresAt`.
- `ImageVulnerabilitySuppression` får `justification`, `expiresAt` og `createdAt`.
- Ny mutation for batch, til MCP og agenter: `suppressImageVulnerabilities(input: {items, dryRun})` og `revokeImageVulnerabilitySuppressions(ids)`.
- **Authz per item**: samme regel som i dag (`CanUpdateVulnerability` for minst ett team med workload som bruker `image_name`). Hver item skrives til activity log.
- **Kjent svakhet, uendret fra i dag**: et image som brukes av flere team, deler suppressions.

## Migrering

1. Opprett funksjon, kolonne, enum og tabell.
2. Kopier `suppressed_vulnerabilities WHERE suppressed`:
   - Normaliser `cve_id` til kanonisk via `cve_alias` og `package` via `purl_without_version`.
   - Ved kollisjon (flere versjoner eller aliaser på samme nøkkel) beholdes raden med nyest `updated_at`.
   - Mapping: `created_by = suppressed_by` (eller `'unknown'`), `reason_text`, `state = reason`. Rader med `not_set` hoppes over.
3. Gjenskap MV-ene med ny join.
4. Gi den gamle tabellen nytt navn, `suppressed_vulnerabilities_legacy`, og slett den i en senere release.
5. Regn ut alle summaries på nytt (engangs-jobb).

## Testkrav (observerbar oppførsel)

- `purl_without_version` gir forventet output for eksemplene over (maven, npm med og uten scope, deb med qualifiers, golang, uten versjon).
- En suppression på `pkg@1.33` skjuler funnet for `pkg@1.34` i samme image og på en ny tag. Den påvirker ikke samme pakke og CVE i et annet image.
- Suppression via alias (GHSA) skjuler funnet som er lagret med CVE-ID, og omvendt. Dette gjelder også `ListVulnerabilitiesForImage`.
- Etter `expires_at` telles funnet igjen i summary (etter utløps-cron) og listes uten `include_suppressed`.
- Opprett på eksisterende nøkkel gir én aktiv rad og én tilbaketrukket rad. Tilbaketrekking gjør funnet aktivt igjen.
- `dry_run` skriver ingenting og rapporterer riktig `matched_findings`.
- En batch med én ugyldig item skriver ingenting.
- Migrering: eksisterende suppressions er fortsatt gjeldende, og kollisjoner gir én rad.
- Updateren gjør ingen skrivekall mot DT sitt analysis-API.

## Rekkefølge

1. Modell, migrering og matching, og fjerning av synken til DT og aliaslogikken (v13s). Eksisterende API uendret, med ny semantikk.
2. Utløp og justification, `CreateSuppressions`/`RevokeSuppressions`/`ListSuppressions` og CLI-støtte.
3. nais api: nye felt og batch-mutation, deretter Console og MCP.

## Åpne beslutninger

- **Standard utløpsdato.** Alternativene er ingen (anbefalt i v1, valgfritt felt) eller for eksempel 12 måneder påkrevd.
- **Breddere suppressions ved migrering.** Eksisterende suppressions blir gjeldende for alle versjoner av pakken. Anbefalt ja, siden det er nettopp det som er ønsket.
- **Stopp av synken til DT.** Bekreft at ingen bruker DT-UI eller DT-varsler og forventer suppressions der.
- **`IN_TRIAGE` og `RESOLVED` som tilstander.** Beholdes for kompatibilitet. Vurder å avvikle dem senere til fordel for kun VEX-tilstander.
