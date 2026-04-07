# zipstream

Browse remote ZIP files without downloading them.
Uses HTTP range requests to fetch only the central directory, then streams individual files on demand.

## Install

```bash
pip install flask
```

## Run

```bash
python app.py
```

Then open → http://localhost:5000

## Usage

- Paste a ZIP URL into the form and hit Browse
- Navigate folders, click files to view/stream them
- Renderable in-browser: images, video, audio, text, code, JSON, PDF
- Force-download: .exe .zip .py .bin .deb etc.
- Direct URL: http://localhost:5000/browse?url=https://example.com/archive.zip
- View a file: http://localhost:5000/download?url=...&entry=folder/file.txt&view=1
- Download a file: http://localhost:5000/download?url=...&entry=folder/file.txt

## How it works

1. HEAD request → gets total file size, confirms Accept-Ranges: bytes
2. Range request on last 128KB → locates + parses EOCD (End of Central Directory)
3. Range request on Central Directory → gets all file names, sizes, offsets
4. Metadata cached to ~/.zipstream_cache.db (SQLite)
5. When you open a file → range request on just that file's bytes → decompress → serve

Supports: DEFLATE (method 8), STORE (method 0), ZIP64

## Notes

- Server must support range requests (most static file hosts do)
- Password-protected ZIPs won't work (by design)
- Cache stores only metadata, never file contents
- Hit ↺ Refresh in the topbar to re-fetch directory from server
