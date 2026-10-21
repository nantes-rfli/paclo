#!/usr/bin/env python3
"""Resolve production and scanner independently, run NVD, verify evidence. No aliases."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'dev/audit'
UTC = timezone.utc
ENGINE = '12.2.2'
NVD = '5.3.0'
MAX_AGE = timedelta(hours=24)


def now():
    return datetime.now(UTC)


def stamp(value):
    return value.isoformat().replace('+00:00', 'Z')


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return result.astimezone(UTC)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def sha256(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def inventory(classpath):
    jars, skipped = [], []
    for entry in classpath.strip().split(os.pathsep):
        path = Path(entry).resolve()
        if path.suffix == '.jar':
            if not path.is_file():
                raise ValueError(f'Missing JAR: {path}')
            # tools.deps Maven paths retain selected version and classifier.
            jars.append({'path': str(path), 'file': path.name,
                         'version': path.parent.name, 'sha256': sha256(path)})
        elif path.is_file():
            raise ValueError(f'Unexpected non-JAR scan input: {path}')
        else:
            skipped.append(str(path))
    if not jars:
        raise ValueError('Empty JAR inventory')
    return {'jars': jars, 'excluded_directories': skipped}


def isolated(production):
    for jar in production['jars']:
        if jar['file'].startswith(('nvd-clojure-', 'dependency-check-')):
            raise ValueError('Audit tool leaked into production scan')


def verify_logs(logs):
    # Pinned upstream logging uses bracketed date/thread prefixes. Some upstream
    # integrations can log a remote failure while retaining cached data.
    for log in logs:
        for line in log.splitlines():
            if re.search(r'^(?:\[[^\]\n]*\]\s*)*ERROR\b', line):
                raise ValueError('Scanner logged an error; inspect scanner logs')
            if re.search(r'\bWARN\b.*(?:unable to (?:update|connect|download)|'
                         r'error (?:updating|downloading|analy[sz]ing)|'
                         r'failed to (?:update|download|analy[sz]e)|'
                         r'using (?:local|cached) data|HTTP (?:401|403|429))', line, re.I):
                raise ValueError('Scanner logged an incomplete remote/analysis operation')


def scores(vulnerability):
    values = []
    for field, score_field in [('cvssv2', 'score'), ('cvssv3', 'baseScore'),
                               ('cvssv4', 'baseScore')]:
        if field in vulnerability:
            value = vulnerability[field].get(score_field)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or not 0 <= value <= 10):
                raise ValueError('Missing or invalid CVSS base score')
            values.append(value)
    if not values:
        raise ValueError('Unscored vulnerability requires triage; cannot pass')
    return values


def validate(report, production, started, finished, refresh=False):
    """Fail closed on stale/partial reports; retain findings even on scan exit != 0."""
    isolated(production)
    info = report['scanInfo']
    if info['engineVersion'] != ENGINE:
        raise ValueError('Unexpected Dependency-Check version')
    if info.get('analysisExceptions'):
        raise ValueError('Report contains analysis exceptions')
    report_time = timestamp(report['projectInfo']['reportDate'])
    if not started - timedelta(minutes=2) <= report_time <= finished + timedelta(minutes=5):
        raise ValueError('Report is outside this execution interval')
    sources = {item['name']: item['timestamp'] for item in info['dataSource']}
    checked = timestamp(sources['NVD API Last Checked'])
    modified = timestamp(sources['NVD API Last Modified'])
    if not finished - MAX_AGE <= checked <= finished + timedelta(minutes=5):
        raise ValueError('NVD last checked is stale or in the future')
    if refresh and checked < started - timedelta(minutes=2):
        raise ValueError('Forced refresh did not check NVD during this execution')
    # Modification time is the upstream dataset watermark, not the cache mtime.
    if not finished - timedelta(days=7) <= modified <= checked + timedelta(minutes=5):
        raise ValueError('NVD dataset watermark is stale or inconsistent')
    dependencies = report['dependencies']
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError('Empty/malformed dependency report')
    expected = {j['sha256'] for j in production['jars']}
    observed = set()
    findings = []
    for dep in dependencies:
        entries = [dep] + dep.get('relatedDependencies', [])
        for entry in entries:
            digest = entry.get('sha256')
            if digest in expected:
                observed.add(digest)
            # Embedded/virtual evidence is allowed, an extra physical JAR is not.
            path = entry.get('filePath', '')
            if path.endswith('.jar') and Path(path).is_absolute() and Path(path).is_file():
                if digest not in expected:
                    raise ValueError(f'Unexpected physical JAR in report: {path}')
        if dep.get('suppressedVulnerabilities'):
            raise ValueError('Unexpected suppression in report')
        for vuln in dep.get('vulnerabilities', []):
            findings.append({'dependency': dep['fileName'], 'path': dep['filePath'],
                             'id': vuln['name'], 'source': vuln.get('source'),
                             'severity': vuln.get('severity'),
                             'max_base_score': max(scores(vuln)),
                             'packages': dep.get('packages', [])})
    if observed != expected:
        raise ValueError('Report does not cover every production JAR hash')
    return {'nvd_last_checked': stamp(checked), 'nvd_last_modified': stamp(modified),
            'report_date': stamp(report_time), 'reported_dependencies': len(dependencies),
            'production_jars': len(production['jars']), 'findings': findings,
            'high_findings': sum(f['max_base_score'] >= 7.0 for f in findings)}


def execute(output, data, resolve_only=False, refresh=False):
    # A new folder prevents stale report success, including interrupted executions.
    output.mkdir(parents=True, exist_ok=False)
    started = now()
    summary = {'status': 'incomplete', 'scope': 'production', 'started': stamp(started),
               'nvd_clojure': NVD, 'dependency_check': ENGINE, 'threshold': 7.0,
               'refresh_requested': refresh,
               'data_directory': str(data), 'commands': [],
               'oss_index': ('credentials configured; see scanner log for actual service result'
                             if os.environ.get('ANALYZER_OSSINDEX_USER') and
                             os.environ.get('ANALYZER_OSSINDEX_PASSWORD') else
                             'disabled by nvd-clojure: credentials unavailable'),
               'nvd_token_present': bool(os.environ.get('NVD_API_TOKEN'))}

    def run(name, command, cwd, required=True, timeout=600):
        summary['commands'].append({'name': name, 'argv': command, 'cwd': str(cwd),
                                    'timeout_seconds': timeout})
        write_json(output / 'summary.json', summary)
        print(f'[audit] Starting {name}', flush=True)
        with (output / (name + '.log')).open('w') as log, (
                output / (name + '.stderr.log')).open('w') as errors:
            try:
                result = subprocess.run(command, cwd=cwd, stdout=log, stderr=errors,
                                        timeout=timeout)
            except subprocess.TimeoutExpired as error:
                summary['commands'][-1]['timed_out'] = True
                raise ValueError(f'{name} timed out after {timeout}s; inspect its logs') from error
        summary['commands'][-1]['exit'] = result.returncode
        write_json(output / 'summary.json', summary)
        print(f'[audit] {name} exited {result.returncode}', flush=True)
        if required and result.returncode:
            raise ValueError(f'{name} failed with exit {result.returncode}; see {name}.log')
        return result.returncode

    try:
        run('cli', ['clojure', '-Sdescribe'], ROOT)
        if '"1.12.5.1664"' not in (output / 'cli.log').read_text():
            raise ValueError('Use reference Clojure CLI 1.12.5.1664')
        run('java', ['java', '-version'], ROOT)
        run('source', ['git', 'rev-parse', 'HEAD'], ROOT)
        run('source-status', ['git', 'status', '--short', '--untracked-files=all'], ROOT)
        for label, cwd in [('production', ROOT), ('tool', TOOL)]:
            run(label + '-classpath', ['clojure', '-Srepro', '-Spath'], cwd)
            run(label + '-tree', ['clojure', '-Srepro', '-Stree'], cwd)
            inv = inventory((output / (label + '-classpath.log')).read_text())
            write_json(output / (label + '-jars.json'), inv)
        production = json.loads((output / 'production-jars.json').read_text())
        isolated(production)
        scan_classpath = os.pathsep.join(jar['path'] for jar in production['jars'])
        (output / 'scanner-input-classpath.log').write_text(scan_classpath + '\n')
        if resolve_only:
            summary['status'] = 'resolved-only'
            return 0
        data.mkdir(parents=True, exist_ok=True)
        summary['cache_before'] = [{'file': p.name, 'bytes': p.stat().st_size,
                                    'modified': stamp(datetime.fromtimestamp(p.stat().st_mtime, UTC))}
                                   for p in sorted(data.iterdir()) if p.is_file()]
        scan_exit = run('scanner', ['clojure', '-Srepro', '-J-Dclojure.main.report=stderr',
                                   '-M', 'run.clj', str(ROOT / 'dev/nvd-clojure.edn'),
                                   str(output), str(data),
                                   str(refresh).lower(),
                                   scan_classpath],
                        TOOL, required=False, timeout=18000)
        summary['scanner_exit'] = scan_exit
        versions = json.loads((output / 'tool-versions.json').read_text())
        if versions != {'nvd-clojure': NVD, 'dependency-check': ENGINE}:
            raise ValueError('Unexpected actual tool versions')
        report_path = output / 'dependency-check-report.json'
        report = json.loads(report_path.read_text())
        summary['report_sha256'] = sha256(report_path)
        summary.update(validate(report, production, started, now(), refresh))
        verify_logs([(output / 'scanner.log').read_text(),
                     (output / 'scanner.stderr.log').read_text()])
        # nvd-clojure may fail before writing a report on update/analysis errors.
        # Never turn a nonzero scanner exit into success, even with a valid report.
        if scan_exit:
            summary['status'] = 'failed'
            summary['error'] = f'Scanner failed with exit {scan_exit}; inspect scanner.log'
            return 1
        if summary['high_findings']:
            summary['status'] = 'vulnerabilities'
            return 1
        summary['status'] = 'passed'
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        summary['error'] = str(error)
        return 1
    finally:
        summary['finished'] = stamp(now())
        write_json(output / 'summary.json', summary)
        print(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='New evidence directory (must not exist)')
    parser.add_argument('--data-directory', type=Path,
                        default=ROOT / '.dev-tools/nvd-data' / ENGINE)
    parser.add_argument('--resolve-only', action='store_true', help='No NVD scan; never an audit pass')
    parser.add_argument('--refresh', action='store_true', help='Require an NVD check in this execution')
    args = parser.parse_args()
    try:
        return execute(args.output.resolve(), args.data_directory.resolve(), args.resolve_only,
                       args.refresh)
    except OSError as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    sys.exit(main())
