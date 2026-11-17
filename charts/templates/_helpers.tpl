{{- define "v0s.databaseClusterName" -}}
{{- if .Values.postgresqlEnabled -}}
{{- required "Set postgresql.fullnameOverride to a stable CNPG cluster name" .Values.postgresql.fullnameOverride -}}
{{- else -}}
{{- required "Set database.clusterName to an existing CNPG cluster" .Values.database.clusterName -}}
{{- end -}}
{{- end -}}

{{- define "v0s.databaseRuntimeSecretName" -}}
{{- if .Values.postgresqlEnabled -}}
{{- if not .Values.postgresql.appUser.enabled -}}
{{- fail "postgresql.appUser.enabled must be true: the runtime must not use the database owner" -}}
{{- end -}}
{{- .Values.postgresql.appUser.existingSecret | default (printf "%s-appuser" (include "v0s.databaseClusterName" .)) -}}
{{- else -}}
{{- .Values.database.runtimeSecretName | default (printf "%s-appuser" (include "v0s.databaseClusterName" .)) -}}
{{- end -}}
{{- end -}}

{{- define "v0s.databaseMigrationSecretName" -}}
{{- if .Values.postgresqlEnabled -}}
{{- printf "%s-app" (include "v0s.databaseClusterName" .) -}}
{{- else -}}
{{- .Values.database.migrationSecretName | default (printf "%s-app" (include "v0s.databaseClusterName" .)) -}}
{{- end -}}
{{- end -}}
