{{/* Expand the name of the chart. */}}
{{- define "mycyber.name" -}}
mycyber-dlp
{{- end }}

{{/*
Create a fully qualified app name.
We truncate at 63 chars because Kubernetes enforces this limit.
*/}}
{{- define "mycyber.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/* Common labels */}}
{{- define "mycyber.labels" -}}
helm.sh/chart: {{ include "mycyber.chart" . }}
app.kubernetes.io/name: {{ include "mycyber.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Chart label */}}
{{- define "mycyber.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" -}}
{{- end }}
