{{- define "v0s.databaseClusterName" -}}
{{- if .Values.postgresqlEnabled -}}
{{- required "Set postgresql.fullnameOverride to a stable CNPG cluster name" .Values.postgresql.fullnameOverride -}}
{{- else -}}
{{- required "Set database.clusterName to an existing CNPG cluster" .Values.database.clusterName -}}
{{- end -}}
{{- end -}}
