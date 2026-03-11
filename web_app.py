"""
VirusTotal Bulk Scanner

Run:  python web_app.py [--port 5000]
Open: http://127.0.0.1:PORT (port is chosen automatically if default is busy)
"""

import os
import sys
import socket
import argparse
import webbrowser
import atexit
import signal
import logging
from flask import (
    Flask, render_template, request, redirect,
    url_for, jsonify, send_file, flash,
)
from scanner_engine import ScanEngine, parse_indicators, parse_indicators_detailed

app = Flask(__name__)
app.secret_key = os.urandom(24)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
PID_FILE = os.path.join(DATA_DIR, 'server.pid')
engine = ScanEngine(data_dir=DATA_DIR)


@app.route('/')
def index():
    scans = engine.get_all_scans()
    api_keys = engine.get_api_keys()
    cache_stats = engine.get_cache_stats()
    return render_template(
        'index.html',
        scans=scans,
        api_keys=api_keys,
        has_keys=len(api_keys) > 0,
        cache_stats=cache_stats,
    )


@app.route('/api/keys', methods=['POST'])
def add_api_key():
    key = request.form.get('api_key', '').strip()
    label = request.form.get('label', '').strip()
    success, message = engine.add_api_key(key, label)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': success, 'message': message})
    flash(message, 'success' if success else 'error')
    return redirect(url_for('index'))


@app.route('/api/keys/delete', methods=['POST'])
def delete_api_key():
    key = request.form.get('api_key', '').strip()
    success, message = engine.remove_api_key(key)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': success, 'message': message})
    flash(message, 'success' if success else 'error')
    return redirect(url_for('index'))


@app.route('/scan/new', methods=['POST'])
def new_scan():
    name = request.form.get('scan_name', 'Untitled Scan').strip() or 'Untitled Scan'
    force_rescan = request.form.get('force_rescan') == 'on'

    text_content = ''
    if 'input_file' in request.files:
        f = request.files['input_file']
        if f.filename:
            text_content = f.read().decode('utf-8', errors='ignore')
    if not text_content:
        text_content = request.form.get('input_text', '')

    if not text_content.strip():
        flash('No input provided.', 'error')
        return redirect(url_for('index'))

    scan_id, message, stats = engine.create_scan(name, text_content, force_rescan)
    if scan_id:
        flash(message, 'success')
        return redirect(url_for('scan_detail', scan_id=scan_id))
    flash(message, 'error')
    return redirect(url_for('index'))


@app.route('/scan/<scan_id>')
def scan_detail(scan_id):
    job = engine.get_scan(scan_id)
    if not job:
        flash('Scan not found', 'error')
        return redirect(url_for('index'))
    api_keys = engine.get_api_keys()
    return render_template('scan.html', scan=job, api_keys=api_keys)


@app.route('/api/scan/<scan_id>/start', methods=['POST'])
def start_scan(scan_id):
    success, message = engine.start_scan(scan_id)
    return jsonify({'success': success, 'message': message})


@app.route('/api/scan/<scan_id>/pause', methods=['POST'])
def pause_scan(scan_id):
    success, message = engine.pause_scan(scan_id)
    return jsonify({'success': success, 'message': message})


@app.route('/api/scan/<scan_id>/status')
def scan_status(scan_id):
    job = engine.get_scan(scan_id)
    if not job:
        return jsonify({'error': 'Scan not found'}), 404

    summary = job.to_summary()
    summary['log'] = job.log[-30:]

    results = []
    for ind in job.indicators:
        r = ind.get('result') or {}
        results.append({
            'value': ind['value'],
            'type': ind['type'],
            'status': ind['status'],
            'comment': ind.get('comment', ''),
            'from_cache': ind.get('from_cache', False),
            'rating': r.get('rating', '-'),
            'positives': r.get('positives', '-'),
            'malicious': r.get('malicious', '-'),
            'suspicious': r.get('suspicious', '-'),
            'total': r.get('total', '-'),
            'detection_ratio': r.get('detection_ratio', '-'),
            'detection_display': r.get('detection_display', '-'),
            'found': r.get('found', False),
            'file_type': r.get('file_type', r.get('country', '-')),
        })
    summary['results'] = results
    return jsonify(summary)


@app.route('/api/scan/<scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    success, message = engine.delete_scan(scan_id)
    return jsonify({'success': success, 'message': message})


@app.route('/scan/<scan_id>/download')
def download_xlsx(scan_id):
    xlsx_path = engine.generate_xlsx(scan_id)
    if xlsx_path and os.path.exists(xlsx_path):
        return send_file(
            xlsx_path, as_attachment=True,
            download_name=os.path.basename(xlsx_path),
        )
    flash('Could not generate XLSX.', 'error')
    return redirect(url_for('scan_detail', scan_id=scan_id))


@app.route('/api/scan/preview', methods=['POST'])
def preview_indicators():
    text_content = ''
    if 'input_file' in request.files:
        f = request.files['input_file']
        if f.filename:
            text_content = f.read().decode('utf-8', errors='ignore')
    if not text_content:
        text_content = request.form.get('input_text', '')

    detail = parse_indicators_detailed(text_content)
    indicators = detail['indicators']
    type_counts = {}
    for ind in indicators:
        t = ind['type']
        type_counts[t] = type_counts.get(t, 0) + 1

    cache_hits = engine.count_cache_hits(indicators)
    reject_pct = (
        len(detail['rejected']) / detail['total_lines'] * 100
        if detail['total_lines'] > 0 else 0
    )

    return jsonify({
        'total': len(indicators),
        'types': type_counts,
        'cache_hits': cache_hits,
        'new_lookups': len(indicators) - cache_hits,
        'preview': [{'value': i['value'], 'type': i['type']} for i in indicators[:500]],
        'rejected': detail['rejected'][:20],
        'rejected_count': len(detail['rejected']),
        'duplicates': detail['duplicates'][:20],
        'duplicate_count': len(detail['duplicates']),
        'auto_fixed': detail['auto_fixed'][:10],
        'auto_fixed_count': len(detail['auto_fixed']),
        'reject_percent': round(reject_pct, 1),
        'total_lines': detail['total_lines'],
    })


@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    success, message = engine.clear_cache()
    return jsonify({'success': success, 'message': message})


@app.route('/api/cache/clear-expired', methods=['POST'])
def clear_expired_cache():
    success, message = engine.clear_expired_cache()
    return jsonify({'success': success, 'message': message})


@app.route('/api/quota')
def check_quota():
    results = engine.check_all_quotas()
    return jsonify({'keys': results})


def find_free_port(start=5000, end=5020):
    """Find first available port in [start, end)."""
    for port in range(start, end):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return start


def _write_pid():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))


def _remove_pid():
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception:
        pass


def _suppress_werkzeug_warning():
    """Hide the red 'development server' warning so the console stays calm."""
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    logging.getLogger('flask.app').setLevel(logging.ERROR)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VirusTotal Bulk Scanner')
    parser.add_argument('--port', '-p', type=int, default=None,
                        help='Port (default: auto-find free port 5000-5019)')
    parser.add_argument('--host', default='127.0.0.1', help='Host (default 127.0.0.1)')
    parser.add_argument('--no-browser', action='store_true', help='Do not open browser automatically')
    args = parser.parse_args()

    host = args.host
    port = args.port
    explicit_port = port is not None
    if port is None:
        port = find_free_port(5000, 5020)
    else:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((host, port))
        except OSError:
            old = port
            port = find_free_port(port + 1, 5020)
            print(f"  Port {old} is busy, switching to {port}")

    url = f"http://{host}:{port}"
    print()
    print("  +=============================================+")
    print("  |       VirusTotal Bulk Scanner               |")
    print("  +=============================================+")
    print()
    print(f"  >>> Open in browser: {url}")
    print("  >>> To stop: press Ctrl+C in this window, or close the window.")
    print()
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    atexit.register(_remove_pid)
    signal.signal(signal.SIGTERM, lambda *a: (_remove_pid(), sys.exit(0)))
    _write_pid()
    # Suppress the big red "development server" warning so it doesn't look like a critical error
    _suppress_werkzeug_warning()
    # Use reloader only when user passed an explicit port; otherwise URL can change on restart
    app.run(debug=True, host=host, port=port, use_reloader=explicit_port)
