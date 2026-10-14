#!/usr/bin/env python3
"""Require CI success for the exact immutable release commit, without token output."""
import argparse
import json
import re
import subprocess


def approved(runs, commit):
    candidates = [run for run in runs if run.get('head_sha') == commit and run.get('event') == 'push']
    if not candidates:
        return False
    latest = max(candidates, key=lambda run: (run.get('run_number', 0), run.get('run_attempt', 0)))
    return latest.get('status') == 'completed' and latest.get('conclusion') == 'success'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository) or not re.fullmatch(r'[a-f0-9]{40}', args.commit):
        raise SystemExit('invalid_release_identity')
    # Exact workflow name, not another unrelated successful check.
    endpoint = f'repos/{args.repository}/actions/workflows/ci.yml/runs?head_sha={args.commit}&per_page=100'
    try:
        result = subprocess.run(['gh', 'api', endpoint], capture_output=True, check=True, timeout=30)
        response = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('release_ci_unavailable') from None
    if not approved(response.get('workflow_runs', []), args.commit):
        raise SystemExit('release_ci_not_successful')
    print('Exact source commit CI passed')


if __name__ == '__main__':
    main()
