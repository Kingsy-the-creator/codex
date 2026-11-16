#!/usr/bin/env bash
# Read-only source snapshots, local fixture tests, retained logs; no installs or pushes.
set -euo pipefail
if [ "$(uname -s)" != Linux ]; then echo 'Run this in Linux/WSL, not Git Bash on Windows.' >&2; exit 2; fi
if [ "$#" -lt 1 ]; then echo 'Usage: bash compare-option-d-installer.sh /path/to/claudeai-option-d [new-output-directory]' >&2; exit 2; fi
for tool in git tar python3; do command -v "$tool" >/dev/null || { echo "Missing: $tool" >&2; exit 2; }; done
repo=$1
if [ "$#" -ge 2 ]; then
  out=$2
  if [ -e "$out" ]; then echo 'Refusing existing output directory.' >&2; exit 2; fi
  mkdir -p -- "$out"
else
  out=$(mktemp -d "${TMPDIR:-/tmp}/codex-ci-compare.XXXXXX")
fi
out=$(cd "$out" && pwd)
printf 'label\tcommit\texit\n' > "$out/results.tsv"
failed=0
for label in base head; do
  case "$label" in
    base) ref=d18d77d3b10b268ed1925b8bb612249c414587ef ;;
    head) ref=eef8136d5e7d3a54d0502e99bd8362eea7dd995e ;;
  esac
  git -C "$repo" rev-parse --verify "$ref^{commit}" > "$out/$label.commit"
  snapshot="$out/$label"
  mkdir -- "$snapshot"
  git -C "$repo" archive "$ref" scripts/install | tar -xf - -C "$snapshot"
  set +e
  python3 -I -B -m unittest discover -s "$snapshot/scripts/install" -p test_install_sh.py -v > "$out/$label.log" 2>&1
  code=$?
  set -e
  printf '%s\t%s\t%s\n' "$label" "$ref" "$code" >> "$out/results.tsv"
  if [ "$code" -ne 0 ]; then failed=1; fi
  python3 - "$out/$label.log" "$label" <<'PY'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text(errors='replace')
print(sys.argv[2]+':')
for line in text.splitlines():
    if line.startswith(('FAIL:', 'ERROR:', 'Ran ', 'OK', 'FAILED')) or 'skipped' in line:
        print(line)
if 'Ran ' not in text:
    print('INCOMPLETE: no unittest execution summary')
PY
done
printf '\nEvidence retained at %s\n' "$out"
cat "$out/results.tsv"
printf '\nThese are fixture-test outcomes, not proof that every broader CI job matches the base. Skipped tests are incomplete evidence. Inspect both logs before classifying a failure.\n'
python3 - "$out/base.log" "$out/head.log" <<'PY'
import pathlib,re,sys
incomplete=[]
for name in sys.argv[1:]:
    text=pathlib.Path(name).read_text(errors='replace')
    if not re.search(r'^Ran [1-9][0-9]* tests? in ',text,re.M) or re.search(r'\.\.\. skipped |^OK \(skipped=',text,re.M):
        incomplete.append(name)
if incomplete:
    print('INCOMPLETE comparison; skipped or missing test execution:',*incomplete,sep='\n')
    sys.exit(2)
PY
exit "$failed"
