#!/usr/bin/env python3
"""Bounded offline AST caller analysis and reviewable unified diff; no source execution."""
import difflib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('CALLER_DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def finite(_): raise ValueError('CALLER_NONFINITE_NUMBER')


def patch(path, before, after):
    lines = difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile='a/'+path, tofile='b/'+path)
    return ''.join(line if line.endswith('\n') else line+'\n\\ No newline at end of file\n' for line in lines)


def main():
    try:
        raw = sys.stdin.buffer.read(4*1024*1024+1)
        if len(raw)>4*1024*1024: raise ValueError('CALLER_INPUT_BUDGET_EXCEEDED')
        manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=finite, parse_float=lambda _: finite('decimal'))
        encoded = json.dumps(manifest,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
        result = subprocess.run(['node','--max-old-space-size=256',str(ROOT/'packages/caller-analysis/analysis.cjs')],
            input=encoded,capture_output=True,timeout=10,check=False,cwd=ROOT)
        if result.returncode or len(result.stdout)>8*1024*1024: raise ValueError('CALLER_ANALYSIS_REJECTED')
        output = json.loads(result.stdout)
        sources = {source['path']:source['content'] for source in manifest['sources']}
        for proposal in output['proposals']:
            text = patch(proposal['source_path'],sources[proposal['source_path']],proposal['patched_content'])
            import hashlib
            proposal['patch_text'] = text
            proposal['patch_sha256'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
        sys.stdout.write(json.dumps(output,ensure_ascii=False,allow_nan=False))
        return 0
    except (OSError,ValueError,KeyError,TypeError,RecursionError,subprocess.TimeoutExpired):
        # Never echo source, paths, environment or raw subprocess diagnostics.
        print('Caller analysis unavailable or input rejected',file=sys.stderr)
        return 1


if __name__=='__main__': raise SystemExit(main())
