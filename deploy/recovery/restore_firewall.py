#!/usr/bin/env python3
"""Re-admit a recovered bridge to owned managed VPN exits before service activation."""
import argparse
import json
import subprocess
from reconcile import admit_restored_bridge
from recovery import read_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--new-bridge', required=True)
    args = parser.parse_args()
    try:
        result = admit_restored_bridge(read_config(args.config), args.new_bridge)
    except ValueError as error:
        if str(error) == 'static_exit_firewall_operator_admission_required':
            raise SystemExit('static_exit_firewall_operator_admission_required: verify the static exit provider firewall permits the new bridge and pinned SSH access, then retry restore') from None
        raise SystemExit('restored_bridge_firewall_admission_failed') from None
    except (OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('restored_bridge_firewall_admission_failed') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
