"""Regression cases for incomplete audits, scope drift and the CVSS boundary."""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import timedelta
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import dependency_audit as audit


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.time = audit.now()
        self.production = {'jars': [{'file': 'library-1.jar', 'sha256': 'abc'}]}
        self.report = {
            'scanInfo': {'engineVersion': audit.ENGINE, 'dataSource': [
                {'name': 'NVD API Last Checked', 'timestamp': audit.stamp(self.time)},
                {'name': 'NVD API Last Modified', 'timestamp': audit.stamp(self.time)}]},
            'projectInfo': {'reportDate': audit.stamp(self.time)},
            'dependencies': [{'fileName': 'library-1.jar', 'filePath': '/abs/library-1.jar',
                              'sha256': 'abc'}]}

    def verify(self):
        return audit.validate(self.report, self.production, self.time, self.time)

    def test_complete_report_and_related_jar(self):
        self.assertEqual(0, self.verify()['high_findings'])
        dep = self.report['dependencies'][0]
        dep['relatedDependencies'] = [{'sha256': dep.pop('sha256')}]
        self.assertEqual(1, self.verify()['production_jars'])

    def test_base_scores_include_exact_seven_and_v4(self):
        for field, key in [('cvssv2', 'score'), ('cvssv3', 'baseScore'), ('cvssv4', 'baseScore')]:
            for score, expected in [(6.9, 0), (7.0, 1), (7.1, 1), (10, 1)]:
                with self.subTest(field=field, score=score):
                    self.report['dependencies'][0]['vulnerabilities'] = [
                        {'name': 'CVE-test', field: {key: score, 'impactScore': 1.0}}]
                    self.assertEqual(expected, self.verify()['high_findings'])

    def test_max_score_across_versions(self):
        self.report['dependencies'][0]['vulnerabilities'] = [
            {'name': 'CVE-test', 'cvssv2': {'score': 7.5}, 'cvssv3': {'baseScore': 5.0}}]
        self.assertEqual(1, self.verify()['high_findings'])

    def test_no_score_invalid_score_or_suppression_cannot_pass(self):
        for value in [None, -1, 11, True, '7', float('nan'), float('inf')]:
            with self.subTest(value=value):
                self.report['dependencies'][0]['vulnerabilities'] = [
                    {'name': 'CVE-test', 'cvssv3': {'baseScore': value}}]
                with self.assertRaises(ValueError):
                    self.verify()
        self.report['dependencies'][0]['vulnerabilities'] = [{'name': 'CVE-test'}]
        with self.assertRaises(ValueError):
            self.verify()
        self.report['dependencies'][0]['suppressedVulnerabilities'] = [{'name': 'CVE-hidden'}]
        with self.assertRaisesRegex(ValueError, 'suppression'):
            self.verify()

    def test_report_errors_missing_inputs_and_engine_drift(self):
        original = deepcopy(self.report)
        for mutate in [lambda r: r['scanInfo'].update(analysisExceptions=[{'error': 'HTTP 403'}]),
                       lambda r: r.update(dependencies=[]),
                       lambda r: r['dependencies'][0].update(sha256='wrong'),
                       lambda r: r['scanInfo'].update(engineVersion='12.1.6')]:
            self.report = deepcopy(original)
            mutate(self.report)
            with self.assertRaises(ValueError):
                self.verify()

    def test_stale_report_and_database_fail(self):
        original = deepcopy(self.report)
        for index, age in [(0, timedelta(hours=25)), (1, timedelta(days=8)),
                           (0, -timedelta(hours=1))]:
            self.report = deepcopy(original)
            self.report['scanInfo']['dataSource'][index]['timestamp'] = audit.stamp(self.time - age)
            with self.assertRaises(ValueError):
                self.verify()
        self.report = deepcopy(original)
        self.report['projectInfo']['reportDate'] = audit.stamp(self.time - timedelta(hours=1))
        with self.assertRaises(ValueError):
            self.verify()
        self.report = deepcopy(original)
        self.report['scanInfo']['dataSource'] = []
        with self.assertRaises(KeyError):
            self.verify()

    def test_tool_contamination_and_missing_jar(self):
        self.production['jars'][0]['file'] = 'nvd-clojure-5.3.0.jar'
        with self.assertRaises(ValueError):
            self.verify()
        with self.assertRaises(ValueError):
            audit.inventory('/nonexistent/library.jar')
        with self.assertRaises(ValueError):
            audit.inventory('/nonexistent/directory')

    def test_unexpected_physical_jar_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / 'unexpected.jar'
            jar.write_bytes(b'jar')
            self.report['dependencies'].append({'fileName': jar.name, 'filePath': str(jar),
                                                'sha256': 'other'})
            with self.assertRaises(ValueError):
                self.verify()


class ProcessTests(unittest.TestCase):
    def exercise(self, scan_exit=0, report_kind='valid', resolution_exit=0, resolve_only=False):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            jar = base / 'library-1.jar'
            jar.write_bytes(b'jar bytes')
            output = base / 'evidence'

            def command(argv, **kwargs):
                if '-Sdescribe' in argv:
                    kwargs['stdout'].write('{:version "1.12.5.1664"}')
                if '-Spath' in argv:
                    kwargs['stdout'].write(str(jar))
                    kwargs['stderr'].write('Downloading dependencies...\n')
                    if resolution_exit:
                        return subprocess.CompletedProcess(argv, resolution_exit)
                if 'run.clj' in argv:
                    audit.write_json(output / 'tool-versions.json',
                                     {'nvd-clojure': audit.NVD, 'dependency-check': audit.ENGINE})
                    if report_kind == 'malformed':
                        (output / 'dependency-check-report.json').write_text('{')
                    elif report_kind != 'missing':
                        report = {'scanInfo': {'engineVersion': audit.ENGINE, 'dataSource': [
                            {'name': name, 'timestamp': audit.stamp(audit.now())} for name in
                            ['NVD API Last Checked', 'NVD API Last Modified']]},
                            'projectInfo': {'reportDate': audit.stamp(audit.now())},
                            'dependencies': [{'fileName': jar.name, 'filePath': str(jar),
                                              'sha256': audit.sha256(jar)}]}
                        if report_kind == 'high':
                            report['dependencies'][0]['vulnerabilities'] = [
                                {'name': 'CVE-high', 'cvssv3': {'baseScore': 7.0}}]
                        audit.write_json(output / 'dependency-check-report.json', report)
                    return subprocess.CompletedProcess(argv, scan_exit)
                return subprocess.CompletedProcess(argv, 0)

            with patch.object(audit.subprocess, 'run', side_effect=command), redirect_stdout(io.StringIO()):
                code = audit.execute(output, base / 'data', resolve_only)
            summary = json.loads((output / 'summary.json').read_text())
            return code, summary

    def test_success_requires_scan_and_valid_report(self):
        code, summary = self.exercise()
        self.assertEqual((0, 'passed'), (code, summary['status']))

    def test_nonzero_cannot_be_overridden_by_clean_report(self):
        for scan_exit in [1, 37, 255]:
            code, summary = self.exercise(scan_exit=scan_exit)
            self.assertEqual((1, 'failed'), (code, summary['status']))
            self.assertEqual(scan_exit, summary['scanner_exit'])

    def test_missing_or_malformed_report_is_incomplete(self):
        for kind in ['missing', 'malformed']:
            code, summary = self.exercise(report_kind=kind)
            self.assertEqual((1, 'incomplete'), (code, summary['status']))

    def test_zero_scanner_exit_with_high_finding_fails(self):
        code, summary = self.exercise(report_kind='high')
        self.assertEqual((1, 'vulnerabilities'), (code, summary['status']))

    def test_resolution_failure_never_starts_scanner(self):
        code, summary = self.exercise(resolution_exit=37)
        self.assertEqual((1, 'incomplete'), (code, summary['status']))
        self.assertNotIn('scanner', [c['name'] for c in summary['commands']])

    def test_resolve_only_is_not_audit_success(self):
        code, summary = self.exercise(resolve_only=True)
        self.assertEqual((0, 'resolved-only'), (code, summary['status']))
        self.assertNotIn('scanner', [c['name'] for c in summary['commands']])

    def test_existing_output_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):
                audit.execute(Path(tmp), Path(tmp) / 'data')


if __name__ == '__main__':
    unittest.main()
