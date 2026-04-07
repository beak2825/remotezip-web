#!/usr/bin/env python3
"""
zipstream - Browse remote ZIP files without downloading them.
Range-request based ZIP central directory parser + on-the-fly file streaming.
"""

import os
import io
import json
import zlib
import struct
import sqlite3
import hashlib
import mimetypes
import threading
import urllib.request
import urllib.error
from datetime import datetime
from flask import Flask, request, Response, render_template_string, jsonify, redirect, url_for, stream_with_context

app = Flask(__name__)
DB_PATH = os.path.expanduser("~/.zipstream_cache.db")
db_lock = threading.Lock()

# ──────────────────────────────────────────────
# DATABASE
# ──────────────────────────────────────────────

def db_init():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS zip_cache (
                url_hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                total_size INTEGER,
                entry_count INTEGER,
                fetched_at TEXT,
                entries_json TEXT
            )
        """)
        con.commit()

def url_hash(url):
    return hashlib.sha256(url.encode()).hexdigest()

def cache_get(url):
    h = url_hash(url)
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute(
            "SELECT url, total_size, entry_count, fetched_at, entries_json FROM zip_cache WHERE url_hash=?",
            (h,)
        ).fetchone()
    if row:
        return {
            "url": row[0],
            "total_size": row[1],
            "entry_count": row[2],
            "fetched_at": row[3],
            "entries": json.loads(row[4])
        }
    return None

def cache_set(url, total_size, entries):
    h = url_hash(url)
    now = datetime.utcnow().isoformat()
    entries_json = json.dumps(entries)
    with db_lock:
        with sqlite3.connect(DB_PATH) as con:
            con.execute("""
                INSERT OR REPLACE INTO zip_cache
                (url_hash, url, total_size, entry_count, fetched_at, entries_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (h, url, total_size, len(entries), now, entries_json))
            con.commit()

def cache_list_all():
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT url, total_size, entry_count, fetched_at FROM zip_cache ORDER BY fetched_at DESC"
        ).fetchall()
    return [{"url": r[0], "total_size": r[1], "entry_count": r[2], "fetched_at": r[3]} for r in rows]

# ──────────────────────────────────────────────
# ZIP PARSING (via range requests)
# ──────────────────────────────────────────────

def http_head(url):
    req = urllib.request.Request(url, method='HEAD')
    req.add_header('User-Agent', 'zipstream/1.0')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            size = r.headers.get('Content-Length')
            accept_ranges = r.headers.get('Accept-Ranges', '')
            return int(size) if size else None, accept_ranges
    except Exception as e:
        raise RuntimeError(f"HEAD request failed: {e}")

def http_range(url, start, end):
    req = urllib.request.Request(url)
    req.add_header('User-Agent', 'zipstream/1.0')
    req.add_header('Range', f'bytes={start}-{end}')
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    except Exception as e:
        raise RuntimeError(f"Range request failed ({start}-{end}): {e}")

def find_eocd(data):
    """Find End of Central Directory record signature."""
    sig = b'PK\x05\x06'
    # Search from end
    pos = data.rfind(sig)
    if pos == -1:
        raise ValueError("EOCD signature not found — not a valid ZIP or needs more tail bytes")
    return pos

def parse_eocd(data, base_offset):
    """Parse EOCD record, return (cd_offset, cd_size, total_entries)."""
    # Check for ZIP64 EOCD locator just before EOCD
    zip64_locator_sig = b'PK\x06\x07'
    eocd_offset_in_data = data.rfind(b'PK\x05\x06')
    
    # Try ZIP64 first
    locator_pos = data.rfind(zip64_locator_sig)
    if locator_pos != -1:
        # ZIP64 EOCD locator found
        zip64_eocd_offset = struct.unpack_from('<Q', data, locator_pos + 8)[0]
        zip64_eocd_sig = b'PK\x06\x06'
        zip64_pos = data.find(zip64_eocd_sig)
        if zip64_pos != -1:
            total_entries = struct.unpack_from('<Q', data, zip64_pos + 32)[0]
            cd_size = struct.unpack_from('<Q', data, zip64_pos + 40)[0]
            cd_offset = struct.unpack_from('<Q', data, zip64_pos + 48)[0]
            return cd_offset, cd_size, total_entries

    # Standard EOCD
    pos = eocd_offset_in_data
    disk_entries  = struct.unpack_from('<H', data, pos + 8)[0]
    total_entries = struct.unpack_from('<H', data, pos + 10)[0]
    cd_size       = struct.unpack_from('<I', data, pos + 12)[0]
    cd_offset     = struct.unpack_from('<I', data, pos + 16)[0]
    return cd_offset, cd_size, total_entries

def parse_central_directory(cd_data):
    """Parse central directory records into list of entry dicts."""
    entries = []
    pos = 0
    sig = b'PK\x01\x02'
    while pos < len(cd_data) - 4:
        if cd_data[pos:pos+4] != sig:
            break
        compress_method   = struct.unpack_from('<H', cd_data, pos + 10)[0]
        mod_time_raw      = struct.unpack_from('<H', cd_data, pos + 12)[0]
        mod_date_raw      = struct.unpack_from('<H', cd_data, pos + 14)[0]
        crc32             = struct.unpack_from('<I', cd_data, pos + 16)[0]
        compressed_size   = struct.unpack_from('<I', cd_data, pos + 20)[0]
        uncompressed_size = struct.unpack_from('<I', cd_data, pos + 24)[0]
        fname_len         = struct.unpack_from('<H', cd_data, pos + 28)[0]
        extra_len         = struct.unpack_from('<H', cd_data, pos + 30)[0]
        comment_len       = struct.unpack_from('<H', cd_data, pos + 32)[0]
        local_header_off  = struct.unpack_from('<I', cd_data, pos + 42)[0]

        fname_bytes = cd_data[pos+46 : pos+46+fname_len]
        try:
            fname = fname_bytes.decode('utf-8')
        except UnicodeDecodeError:
            fname = fname_bytes.decode('cp437', errors='replace')

        # Decode MS-DOS timestamp
        try:
            second = (mod_time_raw & 0x1F) * 2
            minute = (mod_time_raw >> 5) & 0x3F
            hour   = (mod_time_raw >> 11) & 0x1F
            day    = mod_date_raw & 0x1F
            month  = (mod_date_raw >> 5) & 0x0F
            year   = ((mod_date_raw >> 9) & 0x7F) + 1980
            dt = datetime(year, month, day, hour, minute, second)
            mod_str = dt.strftime('%Y-%m-%d %H:%M')
        except Exception:
            mod_str = '—'

        # Handle ZIP64 extended info in extra field
        extra = cd_data[pos+46+fname_len : pos+46+fname_len+extra_len]
        if compressed_size == 0xFFFFFFFF or uncompressed_size == 0xFFFFFFFF or local_header_off == 0xFFFFFFFF:
            epos = 0
            while epos < len(extra) - 4:
                eid  = struct.unpack_from('<H', extra, epos)[0]
                elen = struct.unpack_from('<H', extra, epos+2)[0]
                if eid == 0x0001:  # ZIP64 extended info
                    vals = []
                    for i in range(elen // 8):
                        vals.append(struct.unpack_from('<Q', extra, epos+4+i*8)[0])
                    idx = 0
                    if uncompressed_size == 0xFFFFFFFF and idx < len(vals):
                        uncompressed_size = vals[idx]; idx += 1
                    if compressed_size == 0xFFFFFFFF and idx < len(vals):
                        compressed_size = vals[idx]; idx += 1
                    if local_header_off == 0xFFFFFFFF and idx < len(vals):
                        local_header_off = vals[idx]
                    break
                epos += 4 + elen

        is_dir = fname.endswith('/')
        entries.append({
            "name": fname,
            "is_dir": is_dir,
            "compress_method": compress_method,
            "compressed_size": compressed_size,
            "uncompressed_size": uncompressed_size,
            "local_header_offset": local_header_off,
            "crc32": crc32,
            "modified": mod_str,
        })
        pos += 46 + fname_len + extra_len + comment_len
    return entries

def fetch_zip_directory(url):
    """Full pipeline: HEAD → range tail → parse EOCD → range CD → return entries."""
    total_size, accept_ranges = http_head(url)
    if total_size is None:
        raise RuntimeError("Server did not return Content-Length")
    if 'bytes' not in accept_ranges.lower():
        raise RuntimeError("Server does not support range requests (Accept-Ranges != bytes)")

    # Fetch last 128KB (handles large comments / ZIP64)
    tail_size = min(131072, total_size)
    tail_start = total_size - tail_size
    tail = http_range(url, tail_start, total_size - 1)

    cd_offset, cd_size, total_entries = parse_eocd(tail, tail_start)

    # If central directory is within our tail, use it; else fetch separately
    cd_start_in_tail = cd_offset - tail_start
    if cd_start_in_tail >= 0 and cd_start_in_tail + cd_size <= len(tail):
        cd_data = tail[cd_start_in_tail : cd_start_in_tail + cd_size]
    else:
        cd_data = http_range(url, cd_offset, cd_offset + cd_size - 1)

    entries = parse_central_directory(cd_data)
    return total_size, entries

# ──────────────────────────────────────────────
# FILE STREAMING
# ──────────────────────────────────────────────

LOCAL_HEADER_FIXED = 30  # bytes before variable fields

def stream_entry(url, entry):
    """Fetch and decompress a single ZIP entry on-the-fly."""
    off = entry['local_header_offset']
    # Read local file header to get actual variable field lengths
    header_data = http_range(url, off, off + LOCAL_HEADER_FIXED - 1)
    if header_data[:4] != b'PK\x03\x04':
        raise RuntimeError("Bad local file header signature")
    fname_len  = struct.unpack_from('<H', header_data, 26)[0]
    extra_len  = struct.unpack_from('<H', header_data, 28)[0]
    data_start = off + LOCAL_HEADER_FIXED + fname_len + extra_len
    data_end   = data_start + entry['compressed_size'] - 1

    method = entry['compress_method']
    compressed = http_range(url, data_start, data_end)

    if method == 0:
        return compressed
    elif method == 8:
        return zlib.decompress(compressed, -15)
    else:
        raise RuntimeError(f"Unsupported compression method: {method}")

# ──────────────────────────────────────────────
# MIME / RENDER DECISION
# ──────────────────────────────────────────────

RENDER_IN_BROWSER = {
    # text
    '.txt', '.md', '.csv', '.log', '.ini', '.cfg', '.conf', '.yaml', '.yml',
    '.json', '.xml', '.html', '.htm', '.css', '.js', '.ts', '.sh', '.bat',
    '.c', '.cpp', '.h', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.swift',
    '.toml', '.env', '.gitignore', '.dockerfile', '.sql', '.r',
    # media
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico',
    '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.flac',
    '.pdf',
}

FORCE_DOWNLOAD = {
    '.exe', '.msi', '.dll', '.so', '.dylib',
    '.zip', '.gz', '.tar', '.rar', '.7z', '.bz2', '.xz',
    '.bin', '.iso', '.img',
    '.pyc', '.pyo',
    '.deb', '.rpm', '.apk',
}

def should_render(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in FORCE_DOWNLOAD:
        return False
    if ext in RENDER_IN_BROWSER:
        return True
    # Default: try to render text-ish things
    mime, _ = mimetypes.guess_type(filename)
    if mime and (mime.startswith('text/') or mime.startswith('image/') or
                 mime.startswith('video/') or mime.startswith('audio/')):
        return True
    return False

def get_mime(filename):
    ext = os.path.splitext(filename)[1].lower()
    mime_map = {
        '.py': 'text/plain', '.sh': 'text/plain', '.bat': 'text/plain',
        '.rs': 'text/plain', '.go': 'text/plain', '.toml': 'text/plain',
        '.yaml': 'text/plain', '.yml': 'text/plain', '.env': 'text/plain',
        '.gitignore': 'text/plain', '.dockerfile': 'text/plain',
        '.md': 'text/plain', '.log': 'text/plain', '.sql': 'text/plain',
    }
    if ext in mime_map:
        return mime_map[ext]
    mime, _ = mimetypes.guess_type(filename)
    return mime or 'application/octet-stream'

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def fmt_size(n):
    if n is None: return '—'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != 'B' else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"

def build_tree(entries):
    """Build nested folder structure from flat entry list."""
    root = {"__files__": [], "__dirs__": {}}
    for e in entries:
        if e['is_dir']:
            continue
        parts = e['name'].split('/')
        node = root
        for part in parts[:-1]:
            if part not in node['__dirs__']:
                node['__dirs__'][part] = {"__files__": [], "__dirs__": {}}
            node = node['__dirs__'][part]
        node['__files__'].append(e)
    return root

# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

@app.route('/')
def index():
    recent = cache_list_all()
    return render_template_string(HOME_TEMPLATE, recent=recent, fmt_size=fmt_size)

@app.route('/browse')
def browse():
    url = request.args.get('url', '').strip()
    path = request.args.get('path', '')
    if not url:
        return redirect('/')

    error = None
    cached = cache_get(url)
    if cached:
        total_size = cached['total_size']
        entries = cached['entries']
        fetched_at = cached['fetched_at']
        from_cache = True
    else:
        try:
            total_size, entries = fetch_zip_directory(url)
            cache_set(url, total_size, entries)
            fetched_at = datetime.utcnow().isoformat()
            from_cache = False
        except Exception as e:
            error = str(e)
            entries = []
            total_size = 0
            fetched_at = None
            from_cache = False

    # Filter entries to current path
    if path:
        prefix = path if path.endswith('/') else path + '/'
        visible = [e for e in entries if e['name'].startswith(prefix)]
        # strip prefix for display
        stripped = []
        for e in visible:
            ec = dict(e)
            ec['display_name'] = ec['name'][len(prefix):]
            stripped.append(ec)
    else:
        stripped = []
        for e in entries:
            ec = dict(e)
            ec['display_name'] = ec['name']
            stripped.append(ec)

    # Build breadcrumb
    crumbs = []
    if path:
        parts = path.split('/')
        for i, p in enumerate(parts):
            crumbs.append({"name": p, "path": '/'.join(parts[:i+1])})

    # Get immediate children only
    def get_children(entries_list, current_prefix):
        dirs_seen = set()
        files = []
        subdirs = []
        for e in entries_list:
            dn = e['display_name']
            if not dn or dn == '/':
                continue
            parts = dn.split('/')
            if len(parts) == 1 and not e['is_dir']:
                files.append(e)
            elif len(parts) >= 2:
                d = parts[0]
                if d not in dirs_seen:
                    dirs_seen.add(d)
                    full_path = (current_prefix + '/' + d).lstrip('/')
                    subdirs.append({"name": d, "path": full_path})
        return subdirs, files

    subdirs, files = get_children(stripped, path)

    zip_name = url.split('/')[-1].split('?')[0] or 'archive.zip'

    return render_template_string(BROWSE_TEMPLATE,
        url=url, path=path, zip_name=zip_name,
        subdirs=subdirs, files=files, crumbs=crumbs,
        total_size=total_size, entry_count=len(entries),
        fetched_at=fetched_at, from_cache=from_cache,
        error=error, fmt_size=fmt_size
    )

@app.route('/download')
def download():
    url = request.args.get('url', '').strip()
    entry_name = request.args.get('entry', '').strip()
    if not url or not entry_name:
        return "Missing url or entry parameter", 400

    cached = cache_get(url)
    if cached:
        entries = cached['entries']
    else:
        try:
            total_size, entries = fetch_zip_directory(url)
            cache_set(url, total_size, entries)
        except Exception as e:
            return f"Error fetching ZIP directory: {e}", 500

    entry = next((e for e in entries if e['name'] == entry_name), None)
    if not entry:
        return f"Entry not found: {entry_name}", 404
    if entry['is_dir']:
        return "Cannot download a directory", 400

    try:
        data = stream_entry(url, entry)
    except Exception as e:
        return f"Error streaming entry: {e}", 500

    filename = os.path.basename(entry_name)
    mime = get_mime(filename)
    render = should_render(filename)

    disposition = 'inline' if render else 'attachment'

    # For viewer page (text/code/image/video)
    view_param = request.args.get('view', '0')
    if view_param == '1' and render:
        return render_template_string(VIEWER_TEMPLATE,
            url=url, entry=entry_name, filename=filename,
            mime=mime, data=data, fmt_size=fmt_size
        )

    resp = Response(data, mimetype=mime)
    resp.headers['Content-Disposition'] = f'{disposition}; filename="{filename}"'
    resp.headers['Content-Length'] = str(len(data))
    return resp

@app.route('/api/cache')
def api_cache():
    return jsonify(cache_list_all())

@app.route('/api/invalidate', methods=['POST'])
def api_invalidate():
    url = request.json.get('url', '')
    if not url:
        return jsonify({"error": "no url"}), 400
    h = url_hash(url)
    with db_lock:
        with sqlite3.connect(DB_PATH) as con:
            con.execute("DELETE FROM zip_cache WHERE url_hash=?", (h,))
            con.commit()
    return jsonify({"ok": True})

# ──────────────────────────────────────────────
# TEMPLATES
# ──────────────────────────────────────────────

BASE_STYLE = """
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Space+Grotesk:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0b0e;
    --bg2: #111318;
    --bg3: #181b22;
    --border: #1e2330;
    --border2: #2a3045;
    --text: #c8d0e0;
    --text2: #7a8499;
    --text3: #4a5268;
    --accent: #4f8ef7;
    --accent2: #2d6ae0;
    --green: #3ecf8e;
    --yellow: #f5c842;
    --red: #f05a5a;
    --purple: #a78bfa;
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Space Grotesk', sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { font-size: 14px; }
  body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { color: #7db0ff; }

  .topbar {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    display: flex;
    align-items: center;
    gap: 16px;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .logo {
    font-family: var(--mono);
    font-weight: 700;
    font-size: 1.1rem;
    color: var(--accent);
    letter-spacing: -0.5px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .logo span { color: var(--text2); font-weight: 300; }
  .logo-icon { font-size: 1.3rem; }

  .url-form {
    flex: 1;
    display: flex;
    gap: 8px;
    max-width: 700px;
  }
  .url-input {
    flex: 1;
    background: var(--bg3);
    border: 1px solid var(--border2);
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.8rem;
    padding: 8px 12px;
    border-radius: 6px;
    outline: none;
    transition: border-color 0.15s;
  }
  .url-input:focus { border-color: var(--accent); }
  .url-input::placeholder { color: var(--text3); }
  .btn {
    background: var(--accent);
    color: #fff;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    font-family: var(--sans);
    font-size: 0.85rem;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s;
    white-space: nowrap;
  }
  .btn:hover { background: var(--accent2); }
  .btn-ghost {
    background: transparent;
    border: 1px solid var(--border2);
    color: var(--text2);
  }
  .btn-ghost:hover { border-color: var(--accent); color: var(--accent); background: transparent; }
  .btn-sm { padding: 5px 10px; font-size: 0.78rem; }

  .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
  .page-title {
    font-family: var(--mono);
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 6px;
  }
  .page-sub { color: var(--text2); font-size: 0.9rem; margin-bottom: 32px; }

  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  .card-header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--bg3);
  }
  .card-title {
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 500;
    color: var(--text2);
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }

  .file-table { width: 100%; border-collapse: collapse; }
  .file-table th {
    text-align: left;
    padding: 10px 16px;
    font-family: var(--mono);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text3);
    border-bottom: 1px solid var(--border);
    background: var(--bg3);
    font-weight: 400;
  }
  .file-table td {
    padding: 9px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 0.88rem;
  }
  .file-table tr:last-child td { border-bottom: none; }
  .file-table tr:hover td { background: rgba(79,142,247,0.04); }

  .fname {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: var(--mono);
    font-size: 0.83rem;
  }
  .icon { font-size: 1rem; width: 18px; text-align: center; flex-shrink: 0; }
  .size-col { color: var(--text2); font-family: var(--mono); font-size: 0.8rem; white-space: nowrap; }
  .date-col { color: var(--text3); font-family: var(--mono); font-size: 0.78rem; white-space: nowrap; }
  .method-badge {
    font-family: var(--mono);
    font-size: 0.68rem;
    padding: 2px 6px;
    border-radius: 3px;
    background: var(--bg3);
    border: 1px solid var(--border2);
    color: var(--text3);
  }

  .breadcrumb {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 0.82rem;
    flex-wrap: wrap;
    background: var(--bg2);
  }
  .breadcrumb a { color: var(--accent); }
  .breadcrumb .sep { color: var(--text3); }
  .breadcrumb .current { color: var(--text); }

  .meta-bar {
    display: flex;
    gap: 24px;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--bg2);
    flex-wrap: wrap;
  }
  .meta-item { display: flex; flex-direction: column; gap: 2px; }
  .meta-label { font-size: 0.7rem; color: var(--text3); text-transform: uppercase; letter-spacing: 0.6px; font-family: var(--mono); }
  .meta-value { font-size: 0.9rem; font-family: var(--mono); font-weight: 500; color: var(--text); }

  .hero-form {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 32px;
    margin-bottom: 32px;
    text-align: center;
  }
  .hero-form h2 { font-family: var(--mono); font-size: 1.1rem; color: var(--text2); margin-bottom: 16px; }
  .hero-input-row { display: flex; gap: 10px; max-width: 600px; margin: 0 auto; }
  .hero-input {
    flex: 1;
    background: var(--bg3);
    border: 1px solid var(--border2);
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.85rem;
    padding: 12px 16px;
    border-radius: 8px;
    outline: none;
    transition: border-color 0.15s;
  }
  .hero-input:focus { border-color: var(--accent); }
  .hero-input::placeholder { color: var(--text3); }

  .recent-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 12px;
  }
  .recent-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
    text-decoration: none;
    display: block;
  }
  .recent-card:hover { border-color: var(--accent); background: rgba(79,142,247,0.04); }
  .recent-name {
    font-family: var(--mono);
    font-size: 0.85rem;
    color: var(--accent);
    margin-bottom: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .recent-meta { display: flex; gap: 12px; }
  .recent-tag {
    font-size: 0.72rem;
    font-family: var(--mono);
    color: var(--text3);
    background: var(--bg3);
    padding: 2px 7px;
    border-radius: 3px;
  }

  .error-box {
    background: rgba(240,90,90,0.08);
    border: 1px solid rgba(240,90,90,0.3);
    border-radius: 8px;
    padding: 16px 20px;
    color: var(--red);
    font-family: var(--mono);
    font-size: 0.85rem;
    margin: 16px 20px;
  }

  .tag-cached {
    font-size: 0.7rem;
    font-family: var(--mono);
    color: var(--green);
    background: rgba(62,207,142,0.1);
    border: 1px solid rgba(62,207,142,0.25);
    padding: 2px 7px;
    border-radius: 3px;
  }
  .tag-live {
    font-size: 0.7rem;
    font-family: var(--mono);
    color: var(--yellow);
    background: rgba(245,200,66,0.1);
    border: 1px solid rgba(245,200,66,0.25);
    padding: 2px 7px;
    border-radius: 3px;
  }
  .tag-dl {
    font-size: 0.7rem;
    font-family: var(--mono);
    color: var(--text3);
    background: var(--bg3);
    border: 1px solid var(--border2);
    padding: 2px 7px;
    border-radius: 3px;
  }

  .spinner {
    display: inline-block;
    width: 14px; height: 14px;
    border: 2px solid var(--border2);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .loading-overlay {
    display: none;
    position: fixed; inset: 0;
    background: rgba(10,11,14,0.7);
    backdrop-filter: blur(4px);
    z-index: 999;
    align-items: center;
    justify-content: center;
    flex-direction: column;
    gap: 12px;
  }
  .loading-overlay.active { display: flex; }
  .loading-text { font-family: var(--mono); color: var(--text2); font-size: 0.9rem; }

  .empty-dir {
    padding: 32px;
    text-align: center;
    color: var(--text3);
    font-family: var(--mono);
    font-size: 0.85rem;
  }
</style>
"""

HOME_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>zipstream</title>""" + BASE_STYLE + """</head>
<body>
<div class="topbar">
  <a href="/" class="logo"><span class="logo-icon">📦</span>zip<span>stream</span></a>
  <form class="url-form" action="/browse" method="get" onsubmit="showLoad()">
    <input class="url-input" name="url" placeholder="https://example.com/archive.zip" autocomplete="off" autofocus>
    <button class="btn" type="submit">Browse</button>
  </form>
</div>

<div class="loading-overlay" id="loadOverlay">
  <div class="spinner" style="width:28px;height:28px;border-width:3px;"></div>
  <div class="loading-text">Fetching ZIP directory…</div>
</div>

<div class="container">
  <div class="page-title">zipstream</div>
  <div class="page-sub">Browse remote ZIP files without downloading them. Range requests only.</div>

  <div class="hero-form">
    <h2>// paste a zip url</h2>
    <form action="/browse" method="get" onsubmit="showLoad()">
      <div class="hero-input-row">
        <input class="hero-input" name="url" placeholder="https://example.com/archive.zip" autocomplete="off">
        <button class="btn" type="submit" style="padding:12px 24px;">→ Browse</button>
      </div>
    </form>
  </div>

  {% if recent %}
  <div class="card">
    <div class="card-header">
      <span class="card-title">Recent Archives</span>
      <span style="color:var(--text3);font-size:0.78rem;font-family:var(--mono);">{{ recent|length }} cached</span>
    </div>
    <div style="padding:16px;">
      <div class="recent-grid">
        {% for r in recent %}
        <a class="recent-card" href="/browse?url={{ r.url | urlencode }}">
          <div class="recent-name">{{ r.url.split('/')[-1].split('?')[0] or r.url }}</div>
          <div style="font-size:0.72rem;color:var(--text3);font-family:var(--mono);margin-bottom:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ r.url }}</div>
          <div class="recent-meta">
            <span class="recent-tag">{{ fmt_size(r.total_size) }}</span>
            <span class="recent-tag">{{ r.entry_count }} files</span>
            <span class="recent-tag">{{ r.fetched_at[:10] if r.fetched_at else '—' }}</span>
          </div>
        </a>
        {% endfor %}
      </div>
    </div>
  </div>
  {% endif %}
</div>
<script>
function showLoad() {
  document.getElementById('loadOverlay').classList.add('active');
}
</script>
</body></html>
"""

BROWSE_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>{{ zip_name }} — zipstream</title>""" + BASE_STYLE + """</head>
<body>
<div class="topbar">
  <a href="/" class="logo"><span class="logo-icon">📦</span>zip<span>stream</span></a>
  <form class="url-form" action="/browse" method="get" onsubmit="showLoad()">
    <input class="url-input" name="url" value="{{ url }}" autocomplete="off">
    <button class="btn" type="submit">Browse</button>
    <button type="button" class="btn btn-ghost btn-sm" onclick="invalidate('{{ url }}')">↺ Refresh</button>
  </form>
</div>

<div class="loading-overlay" id="loadOverlay">
  <div class="spinner" style="width:28px;height:28px;border-width:3px;"></div>
  <div class="loading-text">Fetching…</div>
</div>

<div class="card" style="margin:16px 24px; border-radius:10px; overflow:hidden;">
  {% if error %}
  <div class="error-box">⚠ {{ error }}</div>
  {% else %}

  <div class="meta-bar">
    <div class="meta-item">
      <span class="meta-label">Archive</span>
      <span class="meta-value" style="font-size:0.85rem;color:var(--accent);">{{ zip_name }}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Total Size</span>
      <span class="meta-value">{{ fmt_size(total_size) }}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Files</span>
      <span class="meta-value">{{ entry_count }}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Status</span>
      <span class="meta-value">
        {% if from_cache %}<span class="tag-cached">● cached</span>
        {% else %}<span class="tag-live">● live</span>{% endif %}
      </span>
    </div>
    {% if fetched_at %}
    <div class="meta-item">
      <span class="meta-label">Fetched</span>
      <span class="meta-value" style="font-size:0.8rem;color:var(--text2);">{{ fetched_at[:16].replace('T',' ') }}</span>
    </div>
    {% endif %}
  </div>

  <div class="breadcrumb">
    <a href="/browse?url={{ url | urlencode }}">🏠 root</a>
    {% for crumb in crumbs %}
    <span class="sep">/</span>
    <a href="/browse?url={{ url | urlencode }}&path={{ crumb.path | urlencode }}">{{ crumb.name }}</a>
    {% endfor %}
  </div>

  <table class="file-table">
    <thead>
      <tr>
        <th>Name</th>
        <th>Size</th>
        <th>Compressed</th>
        <th>Modified</th>
        <th>Method</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {% if crumbs %}
      <tr>
        <td colspan="6">
          <div class="fname">
            <span class="icon">↑</span>
            {% set parent_path = crumbs[:-1]|map(attribute='path')|list|join('/') if crumbs|length > 1 else '' %}
            <a href="/browse?url={{ url | urlencode }}{% if parent_path %}&path={{ parent_path | urlencode }}{% endif %}">..</a>
          </div>
        </td>
      </tr>
      {% endif %}

      {% for d in subdirs %}
      <tr>
        <td>
          <div class="fname">
            <span class="icon">📁</span>
            <a href="/browse?url={{ url | urlencode }}&path={{ d.path | urlencode }}">{{ d.name }}/</a>
          </div>
        </td>
        <td class="size-col">—</td>
        <td class="size-col">—</td>
        <td class="date-col">—</td>
        <td></td>
        <td></td>
      </tr>
      {% endfor %}

      {% for f in files %}
      {% set fname = f.display_name.split('/')[-1] %}
      {% set ext = fname.rsplit('.',1)[-1].lower() if '.' in fname else '' %}
      {% set is_renderable = ext in ['txt','md','json','xml','csv','log','ini','cfg','conf','yaml','yml','toml','env','sh','py','js','ts','html','htm','css','c','cpp','h','rs','go','java','rb','kt','swift','sql','r','bat','gitignore','dockerfile','png','jpg','jpeg','gif','webp','svg','bmp','ico','mp4','webm','ogg','mp3','wav','flac','pdf'] %}
      <tr>
        <td>
          <div class="fname">
            <span class="icon">
              {% if ext in ['png','jpg','jpeg','gif','webp','svg','bmp','ico'] %}🖼️
              {% elif ext in ['mp4','webm','ogg','avi','mov'] %}🎬
              {% elif ext in ['mp3','wav','flac','aac'] %}🎵
              {% elif ext in ['py','js','ts','rs','go','c','cpp','h','java','rb','kt','swift','sh','bat'] %}💻
              {% elif ext in ['json','xml','yaml','yml','toml','csv'] %}📋
              {% elif ext in ['txt','md','log'] %}📄
              {% elif ext in ['pdf'] %}📕
              {% elif ext in ['zip','gz','tar','rar','7z'] %}📦
              {% elif ext in ['exe','msi','deb','apk'] %}⚙️
              {% else %}📄{% endif %}
            </span>
            {% if is_renderable %}
            <a href="/download?url={{ url | urlencode }}&entry={{ f.name | urlencode }}&view=1">{{ fname }}</a>
            {% else %}
            <a href="/download?url={{ url | urlencode }}&entry={{ f.name | urlencode }}">{{ fname }}</a>
            {% endif %}
          </div>
        </td>
        <td class="size-col">{{ fmt_size(f.uncompressed_size) }}</td>
        <td class="size-col">{{ fmt_size(f.compressed_size) }}</td>
        <td class="date-col">{{ f.modified }}</td>
        <td><span class="method-badge">{{ 'deflate' if f.compress_method == 8 else ('store' if f.compress_method == 0 else f.compress_method) }}</span></td>
        <td>
          <a href="/download?url={{ url | urlencode }}&entry={{ f.name | urlencode }}" class="btn btn-ghost btn-sm">↓</a>
        </td>
      </tr>
      {% endfor %}

      {% if not subdirs and not files %}
      <tr><td colspan="6"><div class="empty-dir">Empty directory</div></td></tr>
      {% endif %}
    </tbody>
  </table>
  {% endif %}
</div>

<script>
function showLoad() {
  document.getElementById('loadOverlay').classList.add('active');
}
function invalidate(url) {
  if (!confirm('Re-fetch directory from server?')) return;
  fetch('/api/invalidate', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({url})
  }).then(() => {
    showLoad();
    window.location.reload();
  });
}
</script>
</body></html>
"""

VIEWER_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>{{ filename }} — zipstream</title>""" + BASE_STYLE + """
<style>
.viewer-bar {
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 10px 20px;
  display: flex;
  align-items: center;
  gap: 12px;
  position: sticky; top: 0; z-index: 100;
}
.viewer-path {
  font-family: var(--mono);
  font-size: 0.82rem;
  color: var(--text2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
}
.viewer-path .sep { color: var(--text3); margin: 0 4px; }
pre {
  margin: 24px;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  font-family: var(--mono);
  font-size: 0.82rem;
  line-height: 1.6;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text);
}
.media-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px;
  min-height: 60vh;
}
img, video, audio { max-width: 100%; border-radius: 8px; }
video { max-height: 80vh; }
iframe.pdf-view {
  width: calc(100% - 48px);
  height: calc(100vh - 120px);
  margin: 24px;
  border: 1px solid var(--border);
  border-radius: 8px;
  display: block;
  background: white;
}
.size-note { color: var(--text3); font-family: var(--mono); font-size: 0.78rem; }
</style>
</head>
<body>
<div class="viewer-bar">
  <a href="/" class="logo" style="flex-shrink:0;"><span>📦</span>zip<span style="color:var(--text2);font-weight:300;">stream</span></a>
  <div class="viewer-path">
    {% set parts = entry.split('/') %}
    {% for i, p in parts|enumerate %}
      {% if loop.last %}
        <span style="color:var(--text);">{{ p }}</span>
      {% else %}
        {% set partial = parts[:loop.index]|join('/') %}
        <a href="/browse?url={{ url | urlencode }}&path={{ partial | urlencode }}">{{ p }}</a><span class="sep">/</span>
      {% endif %}
    {% endfor %}
  </div>
  <span class="size-note">{{ fmt_size(data|length) }}</span>
  <a href="/browse?url={{ url | urlencode }}&path={{ entry.rsplit('/',1)[0] | urlencode }}" class="btn btn-ghost btn-sm">← back</a>
  <a href="/download?url={{ url | urlencode }}&entry={{ entry | urlencode }}" class="btn btn-sm">↓ Download</a>
</div>

{% set ext = filename.rsplit('.',1)[-1].lower() if '.' in filename else '' %}

{% if ext in ['png','jpg','jpeg','gif','webp','svg','bmp','ico'] %}
  <div class="media-wrap">
    <img src="data:{{ mime }};base64,{{ data | b64encode }}" alt="{{ filename }}">
  </div>
{% elif ext in ['mp4','webm','ogg'] %}
  <div class="media-wrap">
    <video controls autoplay>
      <source src="data:{{ mime }};base64,{{ data | b64encode }}" type="{{ mime }}">
    </video>
  </div>
{% elif ext in ['mp3','wav','flac','aac'] %}
  <div class="media-wrap" style="flex-direction:column;gap:12px;">
    <div style="font-family:var(--mono);color:var(--text2);">{{ filename }}</div>
    <audio controls autoplay>
      <source src="data:{{ mime }};base64,{{ data | b64encode }}" type="{{ mime }}">
    </audio>
  </div>
{% elif ext == 'pdf' %}
  <iframe class="pdf-view" src="data:application/pdf;base64,{{ data | b64encode }}"></iframe>
{% else %}
  <pre>{{ data | decode_safe }}</pre>
{% endif %}

</body></html>
"""

# ──────────────────────────────────────────────
# JINJA2 FILTERS / GLOBALS
# ──────────────────────────────────────────────

import base64

@app.template_filter('b64encode')
def b64encode_filter(data):
    return base64.b64encode(data).decode('ascii')

@app.template_filter('decode_safe')
def decode_safe_filter(data):
    try:
        return data.decode('utf-8')
    except Exception:
        return data.decode('latin-1', errors='replace')

@app.template_filter('urlencode')
def urlencode_filter(s):
    import urllib.parse
    return urllib.parse.quote(str(s), safe='')

@app.template_global('enumerate')
def jinja_enumerate(it):
    return enumerate(it)

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

if __name__ == '__main__':
    db_init()
    print("📦 zipstream running → http://localhost:5000")
    print(f"   Cache: {DB_PATH}")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
