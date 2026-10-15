#!/usr/bin/env python3
"""Read-only scanner for the PolinRider / XCSSET malware (incident 2026-10).

Usage:  python3 -I scan_repo_iocs.py <dir> [<dir> ...]
        git show origin/HEAD:.github/security/scan_repo_iocs.py | python3 -I - .
Reads files as bytes only. Never executes, imports or evaluates anything it reads, and never calls git/npm/node.
Exit code: 0 = clean or WARN only, 1 = confirmed indicators (INFECTED), 2 = bad arguments.

INFECTED (confirmed): .vscode folderOpen task / auto-tasks on; a font-extension file that is JavaScript or an empty
fa-solid-* decoy; a PolinRider marker in any JS/TS file; XCSSET in project.pbxproj; ignore-file lines naming the
temp_*_push.bat / config.bat droppers; those droppers themselves.
WARN (heuristic only): a config file with a padded/obfuscated >1500-char line but no PolinRider marker.
Also INFECTED: a Git LFS pointer in place of a .vscode / config / ignore / .bat file (hides the real content).
Names are matched case-insensitively; symlinks are followed inside the scanned folder only.
Skips .git, node_modules and virtualenvs (build output is scanned: the worm runs payloads from dist/).
"""
import os
import re
import sys

SKIP_DIRS = {'node_modules', '.git', '.venv', 'venv'}
LFS = b'version https://git-lfs'
CONFIG = re.compile(r'(^|/)([^/]*\.config\.(m|c)?(j|t)s|\.eslintrc(\.c?js)?|\.prettierrc\.c?js)$')
FONT_EXT = re.compile(r'\.(woff2?|ttf|otf|eot|llf|lkf)$', re.I)
FONT_MAGIC = (b'wOF2', b'wOFF', b'\x00\x01\x00\x00', b'OTTO', b'true', b'typ1')
MARKER = re.compile(rb"global\.i ?= ?['\"][^'\"]{1,32}['\"]|global\[['\"](_V|!)['\"]\]|rmcej%otb%|Cot%3t=shtP|_\$_1e42|"
                    rb"function MDy\(|global\['r'\] ?= ?require|\.g\[['\"](_V|!)['\"]\]\s*=|"
                    rb"\[['\"](!|_V)['\"]\]\s*=\s*['\"]A?\d{1,2}-|global\._(H2?|t_s|t_u) ?=|x-payload-b64")
XCSSET = re.compile(rb'base64 (-D|--decode)[^\n"]{0,80}\|\s*(ba)?sh\b|xxd -p -r[^\n"]{0,80}\|\s*(ba)?sh\b|curl -fskL|'
                    rb'p=xcode|>/dev/null 2>&1 &\)|sh -c \\"\$\{A[0-9A-F]{6}\}|[0-9A-F]{18}BDE67E')
DROPPER_LINE = re.compile(rb'^\s*/?(temp_[a-z_]*push|config)\.bat\s*\r?$', re.I | re.M)
DROPPER_FILE = re.compile(r'(^|/)(temp_[a-z_]*push|config)\.bat$', re.I)
JS = re.compile(r'\.(m|c)?(j|t)sx?$')
PAD = re.compile(rb'(?<![ \t])[ \t]{60,}\S')   # lookbehind keeps it linear on long whitespace runs
OBF = re.compile(rb'_0x[0-9a-f]{4,6}')
CMD = re.compile(r'"command"\s*:\s*"((?:[^"\\]|\\.)*)"')
AUTO_ON = re.compile(rb'"task\.allowAutomaticTasks"\s*:\s*(true|"on")')


def payload(data):
    """('INFECTED', why) for a PolinRider marker, ('WARN', why) for padding/obfuscation alone, else None."""
    if MARKER.search(data):
        return 'INFECTED', 'PolinRider payload marker'
    longest = max((len(l) for l in data.splitlines()), default=0)
    if longest > 1500 and (PAD.search(data) or len(OBF.findall(data)) >= 10):
        return 'WARN', f'padded/obfuscated {longest}-char line, no PolinRider marker'
    return None


def kind_of(rel, n):
    rel, n = rel.lower(), n.lower()   # case-insensitive disks (macOS, Windows) load .VSCode/ and x.config.JS too
    if '/.vscode/' in '/' + rel and n.endswith('.json'):
        return 'vscode'
    if FONT_EXT.search(n):
        return 'font'
    if CONFIG.search(rel):
        return 'config'
    if n == 'project.pbxproj':
        return 'pbxproj'
    if n.startswith('.') and n.endswith('ignore'):
        return 'ignore'
    if DROPPER_FILE.search(rel):
        return 'bat'
    if JS.search(n):
        return 'js'
    return None


def inside(root_real, p):
    """Real path of p if it stays inside the scanned folder, else None (never read outside it)."""
    rp = os.path.realpath(p)
    return rp if rp == root_real or rp.startswith(root_real + os.sep) else None


def scan(root):
    hits, files = [], 0
    root_real = os.path.realpath(root)
    seen = {(root_real, False)}
    for d, dirs, names in os.walk(root, followlinks=True):
        keep = []
        for x in dirs:   # follow directory links inside the root; (real dir, under .vscode) visited once -> no cycles
            rp = inside(root_real, os.path.join(d, x))
            key = (rp, '/.vscode/' in '/' + os.path.relpath(os.path.join(d, x), root).lower() + '/')
            if x not in SKIP_DIRS and rp and key not in seen:
                seen.add(key)
                keep.append(x)
        dirs[:] = keep
        for n in names:
            p = os.path.join(d, n)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            kind = kind_of(rel, n)
            real = inside(root_real, p) if kind else None
            try:
                if not real or not os.path.isfile(real):
                    continue
                if kind in ('js', 'font') and os.path.getsize(real) > 2_000_000:
                    continue
                files += 1
                data = open(real, 'rb').read()
            except OSError:
                continue
            if data.startswith(LFS):
                if kind in ('vscode', 'config', 'ignore', 'bat'):
                    hits.append(('INFECTED', rel, 'Git LFS pointer instead of the file: content hidden from scans'))
                elif kind in ('js', 'pbxproj'):
                    hits.append(('WARN', rel, 'Git LFS pointer: content not scanned'))
                continue
            if kind == 'vscode' and b'folderOpen' in data:
                cmds = CMD.findall(data.decode('utf-8', 'ignore'))
                hits.append(('INFECTED', rel, 'auto-run task on folder open: ' + ' | '.join(c[:120] for c in cmds)))
            elif kind == 'vscode' and AUTO_ON.search(data):
                hits.append(('INFECTED', rel, 'turns on automatic tasks (task.allowAutomaticTasks)'))
            elif kind == 'font':
                is_font = data[:4] in FONT_MAGIC or (len(data) > 36 and data[34:36] == b'LP')
                if not is_font and data.strip() and (MARKER.search(data) or b'require(' in data or b'function' in data):
                    hits.append(('INFECTED', rel, 'fake font file (JavaScript)'))
                elif not is_font and not data.strip() and n.lower().startswith('fa-solid-'):
                    hits.append(('INFECTED', rel, 'empty fa-solid decoy left by the attacker (delete it)'))
            elif kind == 'config':
                r = payload(data)
                if r:
                    hits.append((r[0], rel, r[1]))
            elif kind == 'js' and MARKER.search(data):
                hits.append(('INFECTED', rel, 'PolinRider payload marker'))
            elif kind == 'pbxproj' and XCSSET.search(data):
                hits.append(('INFECTED', rel, 'XCSSET build-phase payload in Xcode project'))
            elif kind == 'ignore' and DROPPER_LINE.search(data):
                hits.append(('INFECTED', rel, 'ignore file hides a dropper .bat (attacker line)'))
            elif kind == 'bat' and re.search(rb'LAST_COMMIT_DATE|commit --amend|push -uf', data):
                hits.append(('INFECTED', rel, 'commit-rewriting dropper script'))
    return hits, files


def main():
    """Exit 1 only for INFECTED; 3 for a scanner error (CI must not report that as malware)."""
    sys.stdout.reconfigure(errors='backslashreplace')
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    infected = False
    try:
        for root in sys.argv[1:]:
            hits, files = scan(root)
            state = 'INFECTED' if any(s == 'INFECTED' for s, _, _ in hits) else 'WARN' if hits else 'clean'
            print(f'{root}: checked {files} candidate files -> {state}')
            for sev, rel, why in hits:
                print(f'   {sev} {rel}: {why}')
            infected |= state == 'INFECTED'
    except Exception as e:
        print(f'scanner error: {e!r}')
        return 3
    return 1 if infected else 0


if __name__ == '__main__':
    sys.exit(main())
