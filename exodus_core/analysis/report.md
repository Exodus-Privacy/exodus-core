# Report for _{{ obj.application.name }}_

## APK file
* Path: `{{obj.apk.file}}`
* Size: {{obj.apk.size|filesizeformat}}
* sha256: `{{obj.apk.sha256}}`

## Application
* Name: {{obj.application.name}}
* Package: `{{obj.application.handle}}`
* Version: {{obj.application.version_name}} - `{{obj.application.version_code}}`
* UAID: `{{obj.application.uaid}}`
* Icon hash: `{{obj.application.icon_hash}}`

## Analysis

### Permissions
{% for p in obj.analysis.detailed_permissions %}* `{{p.permission}}` - _{{p.description}}_
{% endfor %}

### Trackers
{% for t in obj.analysis.trackers %}* [{{t.name}}](https://reports.exodus-privacy.eu.org/trackers/{{t.id}}/)
{% endfor %}