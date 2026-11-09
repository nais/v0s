{{- define "v0s.databaseClusterName" -}}
{{- if .Values.postgresqlEnabled -}}
{{- if .Values.postgresql.networkPolicy.enabled -}}
{{- $_ := required "Set postgresql.networkPolicy.apiServerCidrs (computed by Fasit)" .Values.postgresql.networkPolicy.apiServerCidrs -}}
{{- $_ := required "Set postgresql.networkPolicy.dnsCidrs (computed by Fasit)" .Values.postgresql.networkPolicy.dnsCidrs -}}
{{- end -}}
{{- required "Set postgresql.fullnameOverride to a stable CNPG cluster name" .Values.postgresql.fullnameOverride -}}
{{- else -}}
{{- required "Set database.clusterName to an existing CNPG cluster" .Values.database.clusterName -}}
{{- end -}}
{{- end -}}
