"""
File Integrity Monitor - Backend API
Serves real SHA-256 hashes, baseline management, and scan results to the frontend.

Compatible with: Windows, Linux, macOS
Requires: pip install flask flask-cors
Run with: python monitor.py
"""

import json
import os
import sys
import stat
import platform
from datetime import datetime, timezone
from flask import Flask, jsonify, request
from flask_cors import CORS
try:
    from hash_engine import calculate_sha256
except ImportError:
    import hashlib

    def calculate_sha256(path):
        """Fallback SHA-256 calculator if hash_engine.py is missing on Render."""
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

import shutil

# ── Conditional Unix-only imports ─────────────────────────────────────────────
IS_WINDOWS = sys.platform.startswith('win')
if not IS_WINDOWS:
    import pwd
    import grp

app = Flask(__name__)
CORS(app)

BASELINE_FILE = "baseline.json"
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_ATTACK_FILE = os.path.join(PROJECT_DIR, 'quarantine_demo_critical.txt')
OS_NAME = platform.system()   # 'Windows', 'Linux', 'Darwin'


MONITORED_FILES = [
    # Safe demo file: intentionally critical so quarantine can be simulated without touching real OS files
    TEST_ATTACK_FILE,

    # Windows networking / command execution / shell files
    r'C:\Windows\System32\drivers\etc\hosts',
    r'C:\Windows\System32\drivers\etc\networks',
    r'C:\Windows\System32\drivers\etc\protocol',
    r'C:\Windows\System32\drivers\etc\services',
    r'C:\Windows\System32\cmd.exe',
    r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe',
    r'C:\Windows\explorer.exe',

    # Windows admin / system utilities
    r'C:\Windows\System32\notepad.exe',
    r'C:\Windows\System32\taskmgr.exe',
    r'C:\Windows\regedit.exe',
    r'C:\Windows\System32\services.exe',
    r'C:\Windows\System32\svchost.exe',
    r'C:\Windows\System32\winlogon.exe',
    r'C:\Windows\System32\lsass.exe',

    # Registry hive files: may show permission denied, which is realistic for critical files
    r'C:\Windows\System32\config\SAM',
    r'C:\Windows\System32\config\SECURITY',
    r'C:\Windows\System32\config\SYSTEM',
    r'C:\Windows\System32\config\SOFTWARE',
]



RISK_MAP_WINDOWS = {
    TEST_ATTACK_FILE:                         'critical',
    r'C:\Windows\System32\config\SAM':      'critical',
    r'C:\Windows\System32\config\SECURITY': 'critical',
    r'C:\Windows\System32\lsass.exe':       'critical',
    r'C:\Windows\System32\winlogon.exe':    'critical',
    r'C:\Windows\System32\csrss.exe':       'critical',
    r'C:\Windows\System32\config\SYSTEM':   'critical',
    r'C:\Windows\System32\config\SOFTWARE': 'critical',
    r'C:\Windows\System32\config':          'critical',
    r'C:\Windows\System32\ntoskrnl.exe':    'critical',
    r'C:\Windows\System32\hal.dll':         'critical',
    r'C:\Windows\System32\svchost.exe':     'high',
    r'C:\Windows\System32\services.exe':    'high',
    r'C:\Windows\System32\smss.exe':        'high',
    r'C:\Windows\System32\wininit.exe':     'high',
    r'C:\Windows\System32\drivers\etc':     'high',
    r'C:\Windows\System32\powershell.exe':  'medium',
    r'C:\Windows\System32\cmd.exe':         'medium',
    r'C:\Windows\System32\taskmgr.exe':     'medium',
    r'C:\Windows\System32\userinit.exe':    'medium',
    r'C:\Windows\explorer.exe':             'medium',
    r'C:\Windows\SysWOW64':                 'low',
}

RISK_MAP_LINUX = {
    TEST_ATTACK_FILE: 'critical',
    '/etc/passwd': 'critical',
    '/etc/shadow': 'critical',
    '/etc/sudoers': 'critical',
    '/etc/ssh': 'high',
    '/etc/hosts': 'medium',
}

RISK_MAP_MACOS = {
    TEST_ATTACK_FILE: 'critical',
    '/etc/passwd': 'critical',
    '/etc/sudoers': 'critical',
    '/etc/ssh': 'high',
    '/etc/hosts': 'medium',
}

def get_risk_map():
    if OS_NAME == 'Windows':
        return RISK_MAP_WINDOWS
    if OS_NAME == 'Linux':
        return RISK_MAP_LINUX
    if OS_NAME == 'Darwin':
        return RISK_MAP_MACOS
    return {TEST_ATTACK_FILE: 'critical'}


RISK_MAP = get_risk_map() or {TEST_ATTACK_FILE: 'critical'}

def classify_risk(path):
    """Return risk level safely on every OS. Never crash the API."""
    norm = os.path.abspath(path) if path == TEST_ATTACK_FILE else path.replace('\\', os.sep)
    for prefix, level in RISK_MAP.items():
        prefix_norm = os.path.abspath(prefix) if prefix == TEST_ATTACK_FILE else prefix.replace('\\', os.sep)
        if norm.startswith(prefix_norm):
            return level
    return 'low'

# ─── File metadata (cross-platform) ──────────────────────────────────────────
def get_file_meta(path):
    """
    Return (size, permissions, owner) for a path.
    Falls back to platform-safe equivalents on Windows where Unix
    concepts like uid/gid and rwxrwxrwx strings don't apply.
    """
    try:
        st = os.stat(path)

        # Size — works everywhere
        size_bytes = st.st_size
        size = f"{size_bytes / 1024:.1f} KB" if size_bytes >= 1024 else f"{size_bytes} B"

        if IS_WINDOWS:
            # Windows has no Unix permission bits or uid/gid
            perms = _windows_perms(path)
            owner = _windows_owner(path)
        else:
            perms = stat.filemode(st.st_mode)
            owner = _unix_owner(st)

        return size, perms, owner

    except (OSError, PermissionError):
        return 'N/A', 'N/A', 'N/A'


def _unix_owner(st):
    """Resolve uid:gid to name:groupname on Linux/macOS."""
    try:
        owner_name = pwd.getpwuid(st.st_uid).pw_name
    except (KeyError, AttributeError):
        owner_name = str(st.st_uid)
    try:
        group_name = grp.getgrgid(st.st_gid).gr_name
    except (KeyError, AttributeError):
        group_name = str(st.st_gid)
    return f"{owner_name}:{group_name}"


def _windows_perms(path):
    """
    Return a human-readable permission string on Windows.
    Uses the read-only attribute flag; full ACL introspection would
    require pywin32 which is optional, so we keep it lightweight.
    """
    try:
        attrs = os.stat(path).st_file_attributes  # Available on Windows CPython
        readonly = bool(attrs & stat.FILE_ATTRIBUTE_READONLY)
        hidden   = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
        system   = bool(attrs & stat.FILE_ATTRIBUTE_SYSTEM)
        parts = []
        if readonly: parts.append('readonly')
        if hidden:   parts.append('hidden')
        if system:   parts.append('system')
        return ','.join(parts) if parts else 'normal'
    except (AttributeError, OSError):
        return 'N/A'


def _windows_owner(path):
    """
    Return file owner on Windows.
    Uses the `pywin32` library if installed; otherwise returns N/A.
    Install with: pip install pywin32
    """
    try:
        import win32security
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
        return f"{domain}\\{name}"
    except ImportError:
        # pywin32 not installed — graceful fallback
        return 'N/A (install pywin32)'
    except Exception:
        return 'N/A'


# ─── Hashing ──────────────────────────────────────────────────────────────────
def hash_file(path):
    """Hash a file; return sentinel strings on failure."""
    if not os.path.exists(path):
        return 'MISSING'
    try:
        return calculate_sha256(path)
    except PermissionError:
        return 'PERMISSION_DENIED'
    except Exception:
        return 'ERROR'


# ─── Baseline persistence ─────────────────────────────────────────────────────
def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return None
    try:
        with open(BASELINE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None

def save_baseline(data):
    with open(BASELINE_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def now_utc():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

def ensure_demo_file_exists():
    """Create the safe demo critical file if it is missing."""
    if not os.path.exists(TEST_ATTACK_FILE):
        with open(TEST_ATTACK_FILE, 'w', encoding='utf-8') as f:
            f.write('Original safe critical demo file content')

def quarantine_file(path):
    """Move ONLY the safe demo file into a quarantine folder.
    Real Windows system files are never moved, because that could damage the OS.
    """
    try:
        # Safety rule: only quarantine the project demo file
        if os.path.abspath(path) != os.path.abspath(TEST_ATTACK_FILE):
            return {
                'quarantined': False,
                'reason': 'Skipped: real system files are not moved for safety'
            }

        quarantine_dir = os.path.join(PROJECT_DIR, 'quarantine')
        os.makedirs(quarantine_dir, exist_ok=True)

        filename = os.path.basename(path)
        quarantine_path = os.path.join(quarantine_dir, filename)

        if os.path.exists(path):
            # If an older quarantined copy already exists, replace it
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)

            shutil.copy(path, quarantine_path)

            return {
                'quarantined': True,
                'location': quarantine_path
            }

        return {
            'quarantined': False,
            'reason': 'File does not exist'
        }

    except Exception as e:
        return {
            'quarantined': False,
            'error': str(e)
        }

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/api/status', methods=['GET'])
def api_status():
    """Return baseline existence and scan summary without re-hashing."""
    baseline = load_baseline()
    return jsonify({
        'baseline_exists':    baseline is not None,
        'baseline_timestamp': baseline.get('timestamp') if baseline else None,
        'file_count':         len(MONITORED_FILES),
        'platform':           OS_NAME,
    })

@app.route('/api/incident-report', methods=['GET'])
def api_incident_report():
    baseline = load_baseline()
    if not baseline:
        return jsonify({
            'ok': False,
            'error': 'No baseline found. Generate baseline first.'
        }), 400

    baseline_map = {entry['path']: entry for entry in baseline.get('files', [])}

    scan_time = now_utc()
    incidents = []

    for path in MONITORED_FILES:
        curr_hash = hash_file(path)
        base_entry = baseline_map.get(path)
        base_hash = base_entry['hash'] if base_entry else None
        status = _resolve_status(base_hash, curr_hash)
        risk = classify_risk(path)

        if status != 'ok':
            incidents.append({
                'path': path,
                'status': status,
                'risk': risk,
                'baseline_hash': base_hash or '—',
                'current_hash': curr_hash,
                'detected_at': scan_time
            })

    report_lines = []
    report_lines.append('FILE INTEGRITY MONITOR - INCIDENT REPORT')
    report_lines.append('=' * 55)
    report_lines.append(f'Generated At: {scan_time} UTC')
    report_lines.append(f'Platform: {OS_NAME}')
    report_lines.append(f'Total Monitored Files: {len(MONITORED_FILES)}')
    report_lines.append(f'Total Incidents Found: {len(incidents)}')
    report_lines.append('')

    if not incidents:
        report_lines.append('No integrity violations found.')
    else:
        for i, inc in enumerate(incidents, start=1):
            report_lines.append(f'Incident #{i}')
            report_lines.append('-' * 55)
            report_lines.append(f'File Path: {inc["path"]}')
            report_lines.append(f'Status: {inc["status"].upper()}')
            report_lines.append(f'Risk Level: {inc["risk"].upper()}')
            report_lines.append(f'Baseline Hash: {inc["baseline_hash"]}')
            report_lines.append(f'Current Hash: {inc["current_hash"]}')
            report_lines.append(f'Detected At: {inc["detected_at"]} UTC')
            report_lines.append('Recommended Action: Review file, verify source, and restore trusted version.')
            report_lines.append('')

    report_text = '\n'.join(report_lines)

    report_path = os.path.join(PROJECT_DIR, 'incident_report.txt')

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_text)

    return jsonify({
        'ok': True,
        'message': 'Incident report generated',
        'report_path': report_path,
        'incidents': incidents
    })


@app.route('/api/baseline', methods=['GET', 'POST'])
def api_generate_baseline():
    """Hash every monitored file and store as the baseline without crashing on Render/Linux."""
    try:
        ensure_demo_file_exists()
        timestamp = now_utc()
        entries = []

        for path in MONITORED_FILES:
            try:
                digest = hash_file(path)
                size, perms, owner = get_file_meta(path)
                risk = classify_risk(path)
            except Exception as e:
                # One bad/missing/protected file should not break the whole baseline request.
                digest = f'ERROR: {str(e)}'
                size, perms, owner = 'N/A', 'N/A', 'N/A'
                risk = 'low'

            entries.append({
                'path':      path,
                'hash':      digest,
                'size':      size,
                'perms':     perms,
                'owner':     owner,
                'risk':      risk,
                'timestamp': timestamp,
            })

        baseline = {'timestamp': timestamp, 'platform': OS_NAME, 'files': entries}
        save_baseline(baseline)
        return jsonify({'ok': True, 'timestamp': timestamp, 'files': entries}), 200

    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/scan', methods=['GET'])
def api_scan():
    """Hash every monitored file and compare against baseline (single JSON response)."""
    baseline    = load_baseline()
    baseline_map = {}
    if baseline:
        for entry in baseline.get('files', []):
            baseline_map[entry['path']] = entry

    scan_time = now_utc()
    results   = []

    for path in MONITORED_FILES:
        curr_hash  = hash_file(path)
        size, perms, owner = get_file_meta(path)
        base_entry = baseline_map.get(path)
        base_hash  = base_entry['hash'] if base_entry else None
        status     = _resolve_status(base_hash, curr_hash)
        risk       = classify_risk(path)
        quarantine_info = None

        if status == 'modified' and risk == 'critical':
            quarantine_info = quarantine_file(path)

        results.append({
            'path':    path,
            'status':  status,
            'risk':    risk,
            'base':    base_hash or '—',
            'curr':    curr_hash,
            'size':    size,
            'perms':   perms,
            'owner':   owner,
            'checked': scan_time,
            'quarantine': quarantine_info,
        })

    ok_count = len([r for r in results if r['status'] == 'ok'])
    alerts   = len(results) - ok_count
    return jsonify({
        'timestamp':          scan_time,
        'baseline_timestamp': baseline.get('timestamp') if baseline else None,
        'total':   len(results),
        'ok':      ok_count,
        'alerts':  alerts,
        'files':   results,
    })


@app.route('/api/scan/stream', methods=['GET'])
def api_scan_stream():
    """Hash files one-by-one and stream progress via Server-Sent Events."""
    baseline    = load_baseline()
    baseline_map = {}
    if baseline:
        for entry in baseline.get('files', []):
            baseline_map[entry['path']] = entry

    def generate():
        scan_time = now_utc()
        results   = []
        total     = len(MONITORED_FILES)

        yield f"data: {json.dumps({'type':'start','total':total,'scan_time':scan_time})}\n\n"

        for idx, path in enumerate(MONITORED_FILES):
            yield f"data: {json.dumps({'type':'hashing','path':path,'index':idx,'total':total})}\n\n"

            curr_hash  = hash_file(path)
            size, perms, owner = get_file_meta(path)
            base_entry = baseline_map.get(path)
            base_hash  = base_entry['hash'] if base_entry else None
            status     = _resolve_status(base_hash, curr_hash)
            risk       = classify_risk(path)
            quarantine_info = None

            if status == 'modified' and risk == 'critical':
                quarantine_info = quarantine_file(path)

            result = {
                'path':    path,
                'status':  status,
                'risk':    risk,
                'base':    base_hash or '—',
                'curr':    curr_hash,
                'size':    size,
                'perms':   perms,
                'owner':   owner,
                'checked': scan_time,
                'quarantine': quarantine_info,
            }
            results.append(result)
            yield f"data: {json.dumps({'type':'result','index':idx,'total':total,'file':result})}\n\n"

        ok_count = len([r for r in results if r['status'] == 'ok'])
        alerts   = len(results) - ok_count
        yield f"data: {json.dumps({'type':'done','total':total,'ok':ok_count,'alerts':alerts,'files':results})}\n\n"

    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


# ─── Shared helpers ───────────────────────────────────────────────────────────
def _resolve_status(base_hash, curr_hash):
    """Derive file status from baseline hash vs current hash."""
    if base_hash is None:
        return 'new'
    if curr_hash == 'MISSING':
        return 'missing'
    if curr_hash in ('PERMISSION_DENIED', 'ERROR'):
        return 'error'
    if curr_hash != base_hash:
        return 'modified'
    return 'ok'

@app.route('/api/simulate-attack', methods=['POST'])
def api_simulate_attack():
    """Safely simulate a critical-file modification using the demo file.
    This avoids changing real Windows system files while still triggering
    the same hash mismatch + quarantine workflow.
    """
    test_file = TEST_ATTACK_FILE

    try:
        os.makedirs(os.path.dirname(test_file), exist_ok=True)

        if not os.path.exists(test_file):
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write('Original safe critical demo file content')

        with open(test_file, 'a', encoding='utf-8') as f:
            f.write(f"\n# CRITICAL SIMULATED TAMPER EVENT at {now_utc()}")

        return jsonify({
            'ok': True,
            'message': 'Critical file modification simulated',
            'path': test_file,
            'risk': classify_risk(test_file),
            'timestamp': now_utc()
        })

    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e)
        }), 500

# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(f"File Integrity Monitor Backend — {OS_NAME}")
    print(f"Monitoring {len(MONITORED_FILES)} files")
    print("API endpoints:")
    print("  GET  /api/status         — baseline info + platform")
    print("  POST /api/baseline       — generate/refresh baseline")
    print("  GET  /api/scan           — full scan (single response)")
    print("  GET  /api/scan/stream    — live scan (Server-Sent Events)")
    if IS_WINDOWS:
        print("\nWindows note: install pywin32 for file owner resolution.")
        print("  pip install pywin32")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

