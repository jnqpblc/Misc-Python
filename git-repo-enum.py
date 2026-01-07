#!/usr/bin/env python3
print '''
[+] by jnqpblc
# https://www.codestudy.net/blog/listing-all-repositories-served-by-git-daemon/
'''
import argparse
import subprocess
import threading
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import product

print_lock = threading.Lock()


def test_repo(host, repo, timeout):
    url = f"{host.rstrip('/')}/{repo}.git"

    try:
        proc = subprocess.run(
            ["git", "ls-remote", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )

        stderr = proc.stderr.decode(errors="ignore").lower()

        # Public repo
        if proc.returncode == 0:
            return ("public", repo)

        # Exists but restricted
        if any(x in stderr for x in (
            "access denied",
            "not exported",
            "permission denied",
            "authentication required",
        )):
            return ("private", repo)

        return None

    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def generate_candidates(wl1, wl2=None, joiner="_"):
    candidates = set()

    if wl2:
        for a, b in product(wl1, wl2):
            candidates.add(f"{a}{joiner}{b}")
    else:
        candidates.update(wl1)

    return sorted(candidates)


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate Git repositories using git ls-remote"
    )
    parser.add_argument("-H", "--host", required=True,
                        help="Git host (e.g. git://git.example.com)")
    parser.add_argument("-w", "--wordlist", required=True,
                        help="Primary wordlist. E.g., /usr/share/seclists/Discovery/Web-Content/common.txt")
    parser.add_argument("-w2", "--wordlist2",
                        help="Secondary wordlist (enables combinator mode). E.g., /usr/share/seclists/Discovery/Web-Content/common.txt")
    parser.add_argument("-j", "--joiner", default="_",
                        help="Join character for combinator mode (default: _)")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="Number of threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="git ls-remote timeout in seconds (default: 5)")
    parser.add_argument("--show-private", action="store_true",
                        help="Print private/restricted repos during scan")
    args = parser.parse_args()

    wl1 = load_wordlist(args.wordlist)
    wl2 = load_wordlist(args.wordlist2) if args.wordlist2 else None

    candidates = generate_candidates(wl1, wl2, args.joiner)

    # ---- Header (flush fixed) ----
    print(f"[+] Loaded {len(candidates)} unique candidates", flush=True)
    print(f"[+] Target: {args.host}", flush=True)
    print(f"[+] Threads: {args.threads}", flush=True)
    print("-" * 60, flush=True)

    found_public = []
    found_private = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(test_repo, args.host, repo, args.timeout): repo
            for repo in candidates
        }

        for future in as_completed(futures):
            result = future.result()
            if not result:
                continue

            status, repo = result

            with print_lock:
                if status == "public":
                    print(f"[+] PUBLIC: {repo}", flush=True)
                    found_public.append(repo)
                elif status == "private":
                    found_private.append(repo)
                    if args.show_private:
                        print(f"[!] EXISTS (private): {repo}", flush=True)

    # ---- Summary ----
    print("\n" + "=" * 60, flush=True)
    print(f"[+] Public repos found: {len(found_public)}", flush=True)
    print(f"[+] Private repos found: {len(found_private)}", flush=True)

    if found_public:
        print("\n[+] Public repositories:", flush=True)
        for r in found_public:
            print(f"  - {r}", flush=True)

    if args.show_private and found_private:
        print("\n[!] Private repositories:", flush=True)
        for r in found_private:
            print(f"  - {r}", flush=True)


if __name__ == "__main__":
    main()
