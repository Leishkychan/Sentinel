"""
run_scan.py

Quick CLI runner to test Sentinel without the Flask API.
Usage:
    python run_scan.py --target localhost --mode CODE --path /path/to/code
"""

import argparse
import os
from dotenv import load_dotenv

load_dotenv()

from sentinel.core import ScanMode, ScanSession
from sentinel.agents import run_orchestrator, generate_report


def main():
    parser = argparse.ArgumentParser(description="Sentinel — Quick Scan Runner")
    parser.add_argument("--target",  required=True, help="Scan target (must be in APPROVED_TARGETS)")
    parser.add_argument("--mode",    default="CODE", choices=["PASSIVE", "CODE", "PROBE", "ACTIVE"])
    parser.add_argument("--path",    default=None,   help="Path to source code (required for CODE mode)")
    parser.add_argument("--confirm", action="store_true", help="Confirm you have authorization to scan this target")
    args = parser.parse_args()

    if not args.confirm:
        print("\n❌ You must pass --confirm to acknowledge you have authorization to scan this target.")
        print("   Example: python run_scan.py --target localhost --mode CODE --path ./myapp --confirm")
        return

    if args.mode == "ACTIVE":
        print("\n⚠️  ACTIVE mode selected. This will send network requests to the target.")
        confirm = input("Type 'I confirm I have authorization to actively probe this target' to proceed: ")
        if "i confirm i have authorization to actively probe this target" not in confirm.lower():
            print("❌ Confirmation phrase not matched. Aborting.")
            return

    print(f"\n🛡️  Sentinel — starting scan")
    print(f"   Target: {args.target}")
    print(f"   Mode:   {args.mode}")
    print(f"   Path:   {args.path or 'N/A'}")

    session = ScanSession(
        target=args.target,
        mode=ScanMode(args.mode),
        approved=True,
        active_confirmed=(args.mode == "ACTIVE"),
        approved_targets=[args.target],
    )

    result = run_orchestrator(session, source_path=args.path)
    report = generate_report(result)

    print(f"\n✅ Scan complete — {result.total} findings")
    print(f"   CRITICAL: {result.by_severity.get('CRITICAL', 0)}")
    print(f"   HIGH:     {result.by_severity.get('HIGH', 0)}")
    print(f"   MEDIUM:   {result.by_severity.get('MEDIUM', 0)}")
    print(f"   LOW:      {result.by_severity.get('LOW', 0)}")
    print(f"\n📄 Reports saved:")
    print(f"   JSON:     {report['json_path']}")
    print(f"   Markdown: {report['md_path']}")

    if result.summary:
        print(f"\n📋 Summary:\n{result.summary}")


if __name__ == "__main__":
    main()
