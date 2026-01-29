# Karton PDF Analyzer
> [Karton](https://github.com/CERT-Polska/karton) to analyze PDF documents using [Quicksand](https://github.com/tylabs/quicksand).

## Prerequisites

This is to be used as part of a [Karton](https://github.com/CERT-Polska/karton) pipeline. It has been setup as a [Docker](https://www.docker.com/) container.

Recommended **docker compose** setup:

```yml
karton-pdf-analyzer:
  build:
    context: karton/pdf_analyzer
  tty: true
  develop:
    watch:
      - action: sync+restart
        path: karton/pdf_analyzer
        target: /app
        ignore:
          - karton/pdf_analyzer/.venv/
      - action: rebuild
        path: karton/pdf_analyzer/uv.lock
      - action: rebuild
        path: karton/pdf_analyzer/Dockerfile
  depends_on:
    - karton-system
    - mwdb-web
  volumes:
    - ./karton.docker.ini:/etc/karton/karton.ini
```

## Behavior

For a given sample, we will analyze it using **Quicksand** and:
1. Add the detected TTPs as **tags**
2. Add the `risk`, TTPs and their related fields, and extracted urls to the sample as **attributes**
3. Attempt to download any files from extracted URLs and produce them as new samples for further analysis.

**Consumes:**
```json
{"type": "sample", "kind": "document" }
```

**Produces:**
```json
{
  "headers": {"type": "sample", "stage": "analyzed"},
  "payload": {
    "sample": sample,
    "tags": <Mitre TTPs tags>,
    "attributes": {
      "quicksand": <Minimized Quicksand result>,
    }
  }
}

{
  "headers": {"type": "sample", "kind": "raw"},
  "payload": {
    "sample": new_resource,
    "parent": original_sample,
    "comments": "Downloaded from URL: <attempted_url>",
    }
  }
}
```

## Attributes

**Key.** `quicksand`

**Label.** `PDF Analysis by Quicksand`

**Description.** QuickSand is a Python-based analysis framework to analyze suspected malware documents to identify exploits in streams of different encodings or compressions. QuickSand supports documents, PDFs, Mime/Email, Postscript and other common formats. A built-in command line tool can process a single document or directory of documents.

```jinja
<!-- Rich Template -->

{{#value.risk}}
> Risk: **{{.}}**
{{/value.risk}}

{{#value.analysis.length}}
> Analysis
{{/value.analysis.length}}


{{#value.analysis}}
**`{{mitre}}`**: {{description}} | `{{strings}}`

{{/value.analysis}}

{{#value.extracted_urls.length}}
> URLs
{{/value.extracted_urls.length}}

{{#value.extracted_urls}}
- {{.}}
{{/value.extracted_urls}}
```