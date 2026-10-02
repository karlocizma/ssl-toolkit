"""Prometheus metrics, CSV/JSON export and CSV import for the monitors."""
import csv
import io
import json
import time
from datetime import datetime, timezone
from typing import Dict, List

from app.services import cert_monitor, domain_monitor

EXPORT_COLUMNS = ['type', 'id', 'hostname', 'port', 'label', 'tags', 'status', 'issuer', 'not_after',
                  'days_until_expiry', 'last_check', 'serial_number', 'added_at']
MAX_IMPORT = 100


# --------------------------------------------------------------------------- data
def _days_left(not_after_iso):
    if not not_after_iso:
        return None
    dt = datetime.fromisoformat(not_after_iso.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - datetime.now(timezone.utc)).days


def _ts(iso):
    if not iso:
        return None
    dt = datetime.fromisoformat(iso.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def collect() -> Dict[str, List[Dict]]:
    domains = domain_monitor.all_entries()
    certs = cert_monitor._load_monitored_certificates()['certificates']
    return {'domains': domains, 'certificates': certs}


# --------------------------------------------------------------------------- Prometheus
def _esc(value) -> str:
    return str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def _labels(**kw) -> str:
    return '{' + ','.join(f'{k}="{_esc(v)}"' for k, v in kw.items()) + '}'


def render_metrics() -> str:
    data = collect()
    out: List[str] = []

    def family(name, help_text, mtype='gauge'):
        out.append(f'# HELP {name} {help_text}')
        out.append(f'# TYPE {name} {mtype}')

    family('ssl_toolkit_monitored_domains', 'Number of monitored domains')
    out.append(f"ssl_toolkit_monitored_domains {len(data['domains'])}")
    family('ssl_toolkit_monitored_certificates', 'Number of monitored certificates')
    out.append(f"ssl_toolkit_monitored_certificates {len(data['certificates'])}")

    family('ssl_toolkit_domain_up', '1 if the last check could fetch the certificate, 0 if not')
    for d in data['domains']:
        if d.get('status') in ('ok', 'error'):
            out.append(f"ssl_toolkit_domain_up{_labels(hostname=d['hostname'], port=d['port'], label=d.get('label') or d['hostname'])} "
                       f"{1 if d['status'] == 'ok' else 0}")
    family('ssl_toolkit_domain_days_until_expiry', 'Days until the served certificate expires (negative when expired)')
    family('ssl_toolkit_domain_cert_not_after_timestamp_seconds', 'Expiry time of the served certificate')
    family('ssl_toolkit_domain_last_check_timestamp_seconds', 'Time of the last check')
    family('ssl_toolkit_domain_certificate_changes_total', 'Certificate replacements detected', 'counter')
    for d in data['domains']:
        lab = _labels(hostname=d['hostname'], port=d['port'], label=d.get('label') or d['hostname'])
        if d.get('not_after'):
            out.append(f"ssl_toolkit_domain_days_until_expiry{lab} {_days_left(d['not_after'])}")
            out.append(f"ssl_toolkit_domain_cert_not_after_timestamp_seconds{lab} {_ts(d['not_after'])}")
        if d.get('last_check'):
            out.append(f"ssl_toolkit_domain_last_check_timestamp_seconds{lab} {_ts(d['last_check'])}")
        out.append(f"ssl_toolkit_domain_certificate_changes_total{lab} {len(d.get('changes', []))}")

    family('ssl_toolkit_certificate_days_until_expiry', 'Days until a monitored certificate expires')
    for c in data['certificates']:
        out.append(f"ssl_toolkit_certificate_days_until_expiry"
                   f"{_labels(id=c['id'], label=c.get('label') or '', common_name=c.get('common_name') or '')} "
                   f"{_days_left(c['not_after'])}")
    family('ssl_toolkit_scrape_timestamp_seconds', 'Time this exposition was generated')
    out.append(f'ssl_toolkit_scrape_timestamp_seconds {time.time():.0f}')
    return '\n'.join(out) + '\n'


# --------------------------------------------------------------------------- export
def _safe_cell(value):
    """Neutralise spreadsheet formula injection: a cell must not start with = + - @ or control chars."""
    if isinstance(value, str) and value[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


def export_rows() -> List[Dict]:
    data = collect()
    rows = []
    for d in data['domains']:
        rows.append({'type': 'domain', 'id': d['id'], 'hostname': d['hostname'], 'port': d['port'],
                     'label': d.get('label'), 'tags': ';'.join(d.get('tags', [])), 'status': d.get('status'),
                     'issuer': d.get('issuer'), 'not_after': d.get('not_after'),
                     'days_until_expiry': _days_left(d.get('not_after')), 'last_check': d.get('last_check'),
                     'serial_number': d.get('serial_number'), 'added_at': d.get('added_at')})
    for c in data['certificates']:
        rows.append({'type': 'certificate', 'id': c['id'], 'hostname': c.get('common_name'), 'port': None,
                     'label': c.get('label'), 'tags': ';'.join(c.get('tags', [])), 'status': None,
                     'issuer': None, 'not_after': c.get('not_after'),
                     'days_until_expiry': _days_left(c.get('not_after')), 'last_check': None,
                     'serial_number': c.get('serial_number'), 'added_at': c.get('added_at')})
    return rows


def export_csv() -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=EXPORT_COLUMNS)
    writer.writeheader()
    for row in export_rows():
        writer.writerow({k: _safe_cell(row.get(k)) for k in EXPORT_COLUMNS})
    return buf.getvalue()


def export_json() -> str:
    return json.dumps({'exported_at': datetime.now(timezone.utc).isoformat(), 'items': export_rows()}, indent=2)


# --------------------------------------------------------------------------- import
def parse_import_csv(text: str) -> List[Dict]:
    """hostname[,port[,label[,tags]]] per line; an optional header row and # comments are ignored."""
    if len(text) > 200_000:
        raise ValueError('CSV is larger than 200 KB')
    entries = []
    for row in csv.reader(io.StringIO(text)):
        if not row or not row[0].strip() or row[0].strip().startswith('#'):
            continue
        host = row[0].strip().lower()
        if host in ('hostname', 'host', 'domain', 'name') and not entries:
            continue  # header
        port = 443
        if len(row) > 1 and row[1].strip():
            try:
                port = int(row[1].strip())
            except ValueError:
                raise ValueError(f"Invalid port '{row[1].strip()}' for {host}")
        label = row[2].strip() if len(row) > 2 and row[2].strip() else None
        tags = [t.strip() for t in row[3].replace(',', ';').split(';') if t.strip()] if len(row) > 3 else []
        entries.append({'hostname': host, 'port': port, 'label': label, 'tags': tags})
    if not entries:
        raise ValueError('The CSV contains no hosts')
    if len(entries) > MAX_IMPORT:
        raise ValueError(f'At most {MAX_IMPORT} hosts can be imported at once (got {len(entries)})')
    return entries


def import_csv(text: str) -> Dict:
    return domain_monitor.add_domain_entries(parse_import_csv(text))
