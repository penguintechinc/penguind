{{- define "hub-api.name" -}}hub-api{{- end -}}

{{- define "hub-api.labels" -}}
app.kubernetes.io/name: {{ include "hub-api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: penguind
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "hub-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hub-api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Image ref: digest wins over tag (production uses digests). */}}
{{- define "hub-api.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ required "image.tag or image.digest is required" .Values.image.tag }}
{{- end -}}
{{- end -}}

{{/* Whether passthrough mTLS (pod-terminated TLS) is active. */}}
{{- define "hub-api.passthrough" -}}
{{- if eq .Values.ingress.mtls.mode "passthrough" -}}true{{- end -}}
{{- end -}}

{{/* One Cilium egress destination. Args: dict "t" <target map> "port" <int>. Renders nothing if target is empty. */}}
{{- define "hub-api.egressTarget" -}}
{{- $port := .port | toString -}}
{{- if .t.selector }}
- toEndpoints:
    - matchLabels:
        {{- toYaml .t.selector | nindent 8 }}
  toPorts:
    - ports:
        - port: {{ $port | quote }}
          protocol: TCP
{{- end }}
{{- if .t.cidrs }}
- toCIDR:
    {{- toYaml .t.cidrs | nindent 4 }}
  toPorts:
    - ports:
        - port: {{ $port | quote }}
          protocol: TCP
{{- end }}
{{- if .t.fqdns }}
- toFQDNs:
    {{- range .t.fqdns }}
    {{- if contains "*" . }}
    - matchPattern: {{ . | quote }}
    {{- else }}
    - matchName: {{ . | quote }}
    {{- end }}
    {{- end }}
  toPorts:
    - ports:
        - port: {{ $port | quote }}
          protocol: TCP
{{- end }}
{{- end -}}
