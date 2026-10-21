#!/usr/bin/env python3
"""Measure a fixture compiled for the actual JDK, beyond Paclo's release-17 classes."""

import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def verify(output):
    output.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        commands.append({'command': args, 'exit': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        result.check_returncode()
        return result.stdout.strip()

    run(['java', '-version'])
    run(['javac', '-version'])
    cp = run(['clojure', '-Spath', '-A:jacoco'])
    import os
    agent = next(p for p in cp.split(os.pathsep) if 'org.jacoco.agent' in p)
    source = output / 'CoverageProbe.java'
    source.write_text('public class CoverageProbe {\n'
                      '  static int value(int n) { return n == 0 ? 1 : 2; }\n'
                      '  public static void main(String[] args) {\n'
                      '    if (value(0) + value(1) != 3) throw new AssertionError();\n'
                      '  }\n}\n')
    classes = output / 'classes'
    run(['javac', '-d', str(classes), str(source)])
    data = output / 'jacoco.exec'
    run(['java', f'-javaagent:{agent}=destfile={data},append=false,includes=CoverageProbe',
         '-cp', str(classes), 'CoverageProbe'])
    xml = output / 'jacoco.xml'
    run(['java', '-cp', cp, 'org.jacoco.cli.internal.Main', 'report', str(data),
         '--classfiles', str(classes), '--xml', str(xml)])
    counters = {c.attrib['type']: {k: int(c.attrib[k]) for k in ('covered', 'missed')}
                for c in ET.parse(xml).getroot().findall('counter')}
    assert counters['LINE']['covered'] == 3, counters
    assert counters['BRANCH']['covered'] == 3, counters
    major = int.from_bytes((classes / 'CoverageProbe.class').read_bytes()[6:8], 'big')
    (output / 'summary.json').write_text(json.dumps({'class_major': major, 'counters': counters}, indent=2) + '\n')
    print(f'Actual-runtime JaCoCo probe passed (class major {major}): {counters}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    verify(parser.parse_args().output.resolve())
