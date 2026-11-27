"""The secret scan: action.yml, its config module, and the workflow that runs it.

The scan's config and ignore list come from the commit that is not being
judged, so the action's steps that act on them are executed here against a
real repository, not only read; scripts/ci/secret_scan_config.py is driven
in-process.
"""
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml
from _workflows import _action_bash, _named_run, _shipped_action_pin, _workflow

ROOT = Path(__file__).resolve().parents[1]
CONFIG_STEP = "Take the scan's config and ignore list from the trusted commit"
HISTORY_STEP, TREE_STEP = 'Scan the git history', 'Scan the working tree'
CANARY_STEP = 'Prove the scanner flags a planted canary'
ACTION = yaml.load((ROOT / 'action.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
# Shaped like gitleaks' default config: a global path list, a path-only rule allowlist,
# and a BitBake-style one that needs a path AND a line, which stays.
DEFAULT = r"""title = "default"
[allowlist]
description = "global"
paths = [
    '''go\.sum$''',
]
regexes = ['''^true$''']
stopwords = ["abcdefgh"]

[[rules]]
id = "github-pat"
[[rules.allowlists]]
paths = [
    '''README\.md$''',
]

[[rules]]
id = "generic-api-key"
[[rules.allowlists]]
condition = "AND"
paths = ['''\.bb$''']
regexes = ['''LICENSE''']
"""
STRIPPED = {'title': 'default', 'rules': [{'id': 'github-pat'}, {
    'id': 'generic-api-key', 'allowlists': [
        {'condition': 'AND', 'paths': [r'\.bb$'], 'regexes': ['LICENSE']}]}],
    'allowlist': {'description': 'global', 'regexes': ['^true$'], 'stopwords': ['abcdefgh']}}


SPEC = importlib.util.spec_from_file_location(
    'secret_scan_config', ROOT / 'scripts/ci/secret_scan_config.py')
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _git(repo, *arguments):
    # A fixed identity, never the ambient one, and no detached maintenance racing a snapshot.
    config = ('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.com', '-c',
              'commit.gpgsign=false', '-c', 'maintenance.auto=false', '-c', 'gc.auto=0')
    return subprocess.run(['git', '-C', str(repo), *config, *arguments], check=True,
                          capture_output=True, text=True).stdout


def _python3_env(tmp):
    """A BASH_ENV making a step's python3 this interpreter: the suite also runs on Windows."""
    bash_env = Path(tmp) / 'python3.bash'
    bash_env.write_text(f'python3() {{ {shlex.quote(sys.executable)} "$@"; }}\n',
                        encoding='utf-8', newline='\n')
    return str(bash_env)


def _run_step(tmp, name, cwd, runner, gitleaks='', **env):
    if gitleaks:  # the stub takes the binary's place where the download step left it
        (runner / 'gitleaks').write_text(gitleaks, encoding='utf-8', newline='\n')
        (runner / 'gitleaks').chmod(0o755)
    script = Path(tmp) / f'{name}.sh'
    script.write_text(_named_run(ACTION['runs']['steps'], name), encoding='utf-8', newline='\n')
    env = {**os.environ, 'RUNNER_TEMP': str(runner), 'BASH_ENV': _python3_env(tmp), **env}
    return subprocess.run([_action_bash(), '-e', str(script)], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)


def test_secrets_scans_full_history_from_a_trusted_config(tmp):
    del tmp
    workflow = _workflow('secrets.yml')
    events = workflow['on']
    assert set(events) == {'push', 'pull_request', 'schedule', 'workflow_dispatch'}
    assert events['push'] == {'branches': ['main']}, (
        'a scanner must see docs commits, so no paths filter may narrow the push')
    assert not (events['pull_request'] or events['workflow_dispatch'] or {}), (
        'the manual and pull request triggers stay unfiltered')
    assert events['schedule'] == [{'cron': '26 5 * * *'}], (
        "exactly one daily cron, off the hour, clear of codeql Wed '47 3 * * 3' "
        "and scorecard Sat '23 2 * * 6'")
    assert workflow['concurrency'] == {
        'group': 'secrets-${{ github.ref }}', 'cancel-in-progress': 'true'}
    steps = workflow['jobs']['gitleaks']['steps']
    assert steps[:2] == [{**steps[0], 'uses': (
        f"actions/checkout@{_shipped_action_pin('actions/checkout')}")}, {'uses': './'}]
    assert ACTION['runs']['using'] == 'composite'
    steps = ACTION['runs']['steps']
    assert [(step['name'], step['shell']) for step in steps] == [
        ('Download gitleaks and verify its digest', 'bash'), (CONFIG_STEP, 'bash'),
        (HISTORY_STEP, 'bash'), (TREE_STEP, 'bash'), (CANARY_STEP, 'bash')]
    # One release, binary and default rules each frozen by its digest, fetched
    # through one retrying curl; which release is the action's call.
    download = re.sub(r'\s*\\\n\s*', ' ', steps[0]['run'])
    assert re.search(r'fetch\(\) \{\s+curl .*--retry 8 --retry-all-errors .*--output "\$1" "\$2"'
                     r'\s+\}', download), download
    release, = set(re.findall(r'/v(\d+\.\d+\.\d+)/', download))
    tarball = f'gitleaks_{release}_linux_x64.tar.gz'
    lines = [line.strip() for line in download.splitlines()][-6:]
    assert [re.sub('[0-9a-f]{64}', 'D', line) for line in lines] == [
        f'fetch {tarball} https://github.com/gitleaks/gitleaks/releases/download/v{release}/'
        f'{tarball}', f"echo 'D  {tarball}' | sha256sum -c -", f'tar xzf {tarball} gitleaks',
        './gitleaks version', 'fetch gitleaks-default.toml https://raw.githubusercontent.com/'
        f'gitleaks/gitleaks/v{release}/config/gitleaks.toml',
        "echo 'D  gitleaks-default.toml' | sha256sum -c -"], lines
    assert set(steps[1]['env']) == {
        'SECRET_SCAN_ACTION_PATH', 'SECRET_SCAN_EVENT_NAME', 'SECRET_SCAN_BASE_SHA',
        'SECRET_SCAN_BEFORE_SHA', 'SECRET_SCAN_DEFAULT_BRANCH'}
    assert steps[1]['id'] == 'trusted'
    assert not any('continue-on-error' in step for step in steps[2:])
    assert not any('||' in step['run'] for step in steps[2:4]), 'no fallback may weaken a scan'
    assert 'if' not in steps[2], 'the history scan runs only after every earlier step passed'
    # Each still reports when the history scan is red, and never runs on the
    # judged tree's own config: the trusted step must have succeeded.
    assert [step['if'] for step in steps[3:]] == [
        "${{ !cancelled() && steps.trusted.outcome == 'success' }}"] * 2
    config = tomllib.loads((ROOT / '.gitleaks.toml').read_text(encoding='utf-8'))
    assert config == {'extend': {'useDefault': True}}, (
        'the extend line IS the gate; a narrowing allowlist replacement must '
        'fail this suite')


@pytest.mark.parametrize('state', ['tracked', 'file', 'dir', 'link', 'dangling', 'absent', 'lost'])
@pytest.mark.parametrize('leak', [True, False])
@pytest.mark.parametrize('step', [HISTORY_STEP, TREE_STEP])
def test_the_scan_steps_clear_the_judged_exemptions_and_report(tmp, step, leak, state):
    repo, outside = Path(tmp) / 'repo', Path(tmp) / 'outside'
    _git(tmp, 'init', '-q', '-b', 'main', str(repo))
    entries = ('-dash.txt', '.hidden', 'a.txt', 'sub', 'z.txt')
    judged = ('.gitleaksignore', 'sub/.gitleaksignore', '.git/info/attributes')  # one state
    planted = () if state in ('link', 'dangling', 'absent') else judged if state != 'dir' else [
        f'{name}/kept' for name in judged]
    for name in (*entries[:3], 'sub/x', entries[4], '../outside/.gitleaksignore', *planted):
        (repo / name).parent.mkdir(exist_ok=True)
        (repo / name).write_text('x\n', encoding='utf-8', newline='\n')
    targets = {'link': outside / '.gitleaksignore', 'dangling': outside / 'missing'}
    for link, target in [(repo / 'link', outside)] + [
            (repo / name, targets[state]) for name in judged if state in targets]:
        try:  # a symlinked entry is skipped; Windows without symlink rights makes none
            link.symlink_to(target, target_is_directory=target == outside)
        except OSError:
            pass
    if state == 'tracked':  # the top-level file committed as it is, sub's modified since
        _git(repo, 'add', '--', *judged[:2])
        _git(repo, 'commit', '-qm', 'tip')
        (repo / judged[1]).write_text('modified\n', encoding='utf-8', newline='\n')

    def tree():
        return {path: os.readlink(path) if path.is_symlink() else None if path.is_dir()
                else path.read_bytes() for root in (repo, outside) for top, dirs, files in
                os.walk(root) for path in (Path(top, name) for name in dirs + files)}
    before = tree()
    runner, record = Path(tmp) / 'runner-temp', Path(tmp) / 'record'
    copy_dir, report = runner / 'gitleaks-trusted', runner / 'secret-scan-report'
    for directory in (copy_dir, report, record):
        directory.mkdir(parents=True)
    # The stub records each call and reports as gitleaks does; a leaking run finds a leak
    # in the history and in a.txt, and a lost one loses what the step set aside.
    gitleaks = (
        '#!/usr/bin/env bash\n'
        'printf "%s\\t" "$@" >> "$SECRET_SCAN_STUB_ARGV"; echo >> "$SECRET_SCAN_STUB_ARGV"\n'
        'cat .git/info/attributes > "$SECRET_SCAN_STUB_ATTRIBUTES"\n'
        'for f in .gitleaksignore "${@: -1}/.gitleaksignore"; do if [ -e "$f" ] || [ -L "$f" ]; '
        'then echo present; else echo absent; fi; done >> "$SECRET_SCAN_STUB_IGNORE"\n'
        '[ "$SECRET_SCAN_STUB_STATE" != lost ] || rm -rf "$RUNNER_TEMP"/secret-scan-aside.*/*\n'
        'for a; do [ "$prev" = --report-path ] && report=$a; prev=$a; done\n'
        'case "$SECRET_SCAN_STUB_LEAK $1 ${@: -1}" in True\\ detect*) leak=history ;;'
        ' True*\\ a.txt) leak=a.txt ;; *) leak= ;; esac\n'
        'if [ -z "$leak" ]; then echo [] > "$report"; exit 0; fi\n'
        'echo "[{\\"File\\": \\"$leak\\"}]" > "$report"; exit 3\n')
    result = _run_step(tmp, step, repo, runner, gitleaks, SECRET_SCAN_STUB_LEAK=str(leak),
                       SECRET_SCAN_STUB_ARGV=str(record / 'argv'), SECRET_SCAN_STUB_STATE=state,
                       SECRET_SCAN_STUB_ATTRIBUTES=str(record / 'attributes'),
                       SECRET_SCAN_STUB_IGNORE=str(record / 'ignore'))
    failed = 1 if state == 'lost' else leak and (3 if step == HISTORY_STEP else 1)
    assert result.returncode == failed, (
        'a leak anywhere fails the step, and so does a path it cannot put back', result.stderr)
    assert state == 'lost' or tree() == before, 'each moved path is back, and no target written'
    assert step == TREE_STEP or (record / 'attributes').read_text(encoding='utf-8') == '* diff\n', (
        'a plain diff attribute keeps a NUL-bearing blob in the scan; -diff '
        'and an unspecified attribute both hide it from git log -p')
    calls = [line.split('\t')[:-1]
             for line in (record / 'argv').read_text(encoding='utf-8').splitlines()]
    assert (record / 'ignore').read_text(encoding='utf-8').split() == ['absent'] * 2 * len(calls), (
        'no judged .gitleaksignore is left where gitleaks reads one')
    command = 'detect' if step == HISTORY_STEP else 'dir'
    for argv in calls:
        assert argv[:4] == [command, '--verbose', '--redact', '--ignore-gitleaks-allow'], argv
        assert argv[4] == '--config' and Path(argv[5]) == copy_dir / '.gitleaks.toml', argv
        assert argv[6] == '--gitleaks-ignore-path' and Path(argv[7]) == copy_dir, argv
    log_opts = '--full-history --all --diff-filter=uxdb --diff-merges=first-parent'
    if step == HISTORY_STEP:
        argv, = calls
        assert argv[8:12] == [f'--log-opts={log_opts}', '--report-format', 'json',
                              '--report-path'] and Path(argv[12]) == report / 'history.json', argv
        assert len(argv) == 13, 'the walk keeps type changes and merges'
        assert json.loads((report / 'history.json').read_text(encoding='utf-8')) == (
            [{'File': 'history'}] if leak else [])
        return
    # Every checked-out entry is scanned, after a leak too, but never git's own
    # metadata; `--` keeps a leading dash a path.
    assert sorted(argv[12:] for argv in calls) == [['--', name] for name in sorted(entries)], calls
    assert all(argv[8:11] == ['--report-format', 'json', '--report-path'] for argv in calls)
    parts = {Path(argv[11]) for argv in calls}
    assert len(parts) == len(calls), 'no entry overwrites another report'
    assert not any(repo in part.parents or part.parent == report for part in parts), (
        'a part report is neither scanned as the tree nor uploaded beside the merged one')
    assert json.loads((report / 'tree.json').read_text(encoding='utf-8')) == (
        [{'File': 'a.txt'}] if leak else [])


def test_a_tree_with_nothing_to_scan_reports_no_findings(tmp):
    repo, runner = Path(tmp) / 'repo', Path(tmp) / 'runner-temp'
    subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
    (repo / '.gitleaksignore').write_text('kept\n', encoding='utf-8', newline='\n')
    (runner / 'secret-scan-report').mkdir(parents=True)
    result = _run_step(tmp, TREE_STEP, repo, runner,
                       '#!/usr/bin/env bash\necho "$@" >> "$RUNNER_TEMP/calls"\n')
    assert result.returncode == 0 and not (runner / 'calls').exists(), result.stderr
    assert json.loads((runner / 'secret-scan-report/tree.json').read_text(encoding='utf-8')) == []
    # A second run fails before any scan, its part-report directory taken, and puts it back.
    result = _run_step(tmp, TREE_STEP, repo, runner)
    assert result.returncode == 1 and (repo / '.gitleaksignore').read_bytes() == b'kept\n'


@pytest.mark.parametrize('output, status, passes', [
    ('RuleID:      slack-bot-token\n', 1, True), ('FTL unable to load gitleaks config\n', 1, False),
    ('Finding: RuleID: x\n', 1, False), ('RuleID: x\n', 2, False), ('', 0, False)])
def test_the_canary_step_passes_only_on_a_reported_finding(tmp, output, status, passes):
    runner = Path(tmp) / 'runner-temp'
    runner.mkdir()
    gitleaks = ('#!/usr/bin/env bash\nprintf "%s\\n" "$@" > argv\n'
                'cat "${@: -1}/canary.env" > canary\nprintf "$SECRET_SCAN_STUB_OUT"\n'
                'exit "$SECRET_SCAN_STUB_STATUS"\n')
    result = _run_step(tmp, CANARY_STEP, tmp, runner, gitleaks, SECRET_SCAN_STUB_OUT=output,
                       SECRET_SCAN_STUB_STATUS=str(status))
    assert (result.returncode == 0) == passes, (result.stdout, result.stderr)
    assert output in result.stdout, 'the scan output is printed whatever the verdict'
    assert passes or f'(exit {status})' in result.stderr
    trusted = runner / 'gitleaks-trusted'
    argv = (Path(tmp) / 'argv').read_text(encoding='utf-8').splitlines()
    assert argv[:5] == ['dir', '--verbose', '--redact', '--ignore-gitleaks-allow', '--config']
    assert Path(argv[5]) == trusted / '.gitleaks.toml' and argv[6] == '--gitleaks-ignore-path'
    assert Path(argv[7]) == trusted and Path(argv[8]) == runner / 'gitleaks-canary', argv
    assert len(argv) == 9, 'the canary writes no report over the real scans\' reports'
    canary = (Path(tmp) / 'canary').read_text(encoding='utf-8')
    # gitleaks 8.30.1's slack-bot-token rule, which the default rules carry.
    assert re.fullmatch(r'xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\n', canary), canary
    assert canary.strip() not in (ROOT / 'action.yml').read_text(encoding='utf-8'), (
        'a contiguous token in the action would be flagged by its own scan')


def test_the_trusted_config_step_reads_the_trusted_event_commit(tmp):
    repo = Path(tmp) / 'repo'
    repo.mkdir()
    _git(repo, 'init', '-q', '-b', 'main')
    tip_config = '[extend]\nuseDefault = true\n[allowlist]\ndescription = "tip"\n'

    def commit(config, message, ignore=None):
        (repo / '.gitleaks.toml').write_text(config, encoding='utf-8', newline='\n')
        if ignore is None:
            (repo / '.gitleaksignore').unlink(missing_ok=True)
        else:
            (repo / '.gitleaksignore').write_text(ignore, encoding='utf-8', newline='\n')
        _git(repo, 'add', '-A')
        _git(repo, 'commit', '-qm', message)
        return _git(repo, 'rev-parse', 'HEAD').strip()

    tip = commit(tip_config, 'tip')
    commit('[allowlist]\ndescription = "the head exempts itself"\n', 'head',
           ignore='the head exempts itself\n')
    runs = iter(range(100))

    def run(before='', base='', event='push', default_branch=''):
        runner = Path(tmp) / f'runner-temp-{next(runs)}'
        runner.mkdir()
        (runner / 'gitleaks-default.toml').write_text(DEFAULT, encoding='utf-8', newline='\n')
        result = _run_step(tmp, CONFIG_STEP, repo, runner, SECRET_SCAN_ACTION_PATH=str(ROOT),
                           SECRET_SCAN_EVENT_NAME=event, SECRET_SCAN_BASE_SHA=base,
                           SECRET_SCAN_BEFORE_SHA=before, SECRET_SCAN_DEFAULT_BRANCH=default_branch)
        copy_dir = runner / 'gitleaks-trusted'
        stripped = runner / 'gitleaks-default-stripped.toml'
        if result.returncode == 0:
            assert tomllib.loads(stripped.read_text(encoding='utf-8')) == STRIPPED
            assert not any((runner / 'secret-scan-report').iterdir()), 'the report dir starts empty'
        return (result, (copy_dir / '.gitleaks.toml').read_text(encoding='utf-8'),
                (copy_dir / '.gitleaksignore').read_text(encoding='utf-8'), str(stripped))

    result, config, ignored, stripped = run(before=tip)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert tomllib.loads(config) == {'extend': {'path': stripped},
                                     'allowlist': {'description': 'tip'}}, (
        'a push must read the previous tip, its useDefault now the stripped rules')
    assert 'exempts itself' not in ignored, (
        'the judged head\'s .gitleaksignore must never reach the trusted copy')
    result, config, _, _ = run(base=tip, event='pull_request')
    assert result.returncode == 0 and 'description = "tip"' in config, (
        'a pull request must read its base commit')
    _git(repo, 'update-ref', 'refs/remotes/origin/main', tip)
    result, config, _, _ = run(event='schedule')
    assert result.returncode == 0 and 'description = "tip"' in config, (
        'a scheduled scan must read origin/main, not the judged tree')
    _git(repo, 'update-ref', 'refs/remotes/origin/trunk', 'HEAD')
    result, config, _, _ = run(event='workflow_dispatch', default_branch='trunk')
    assert result.returncode == 0 and 'the head exempts itself' in config, (
        'a dispatched scan reads the default branch the event names')
    for named in ({'before': 'not-a-sha'}, {'event': 'pull_request'}):
        result, config, _, stripped = run(**named)
        assert result.returncode == 0 and tomllib.loads(config) == {'extend': {'path': stripped}}, (
            f'{named}: a name that is no commit falls back to the default rules')
    for config_text in ('[extend]\npath = "elsewhere.toml"\n',
                        '[extend]\nPath = "elsewhere.toml"\n',
                        '[extend]\nuseDefault = true\nPath = "elsewhere.toml"\n'):
        result, config, _, _ = run(before=commit(config_text, 'tip redirects'))
        assert result.returncode != 0 and 'sets [extend] path' in result.stderr, (
            f'trusted config {config_text!r} must refuse when it redirects')
        assert config == config_text, 'the refusal reads the trusted file before any rewrite'
    (repo / '.git/shallow').write_text(tip + '\n', encoding='utf-8', newline='\n')
    result = run(before=tip)[0]
    assert result.returncode != 0 and 'shallow' in result.stderr, 'a shallow log is a suffix'


def test_stripping_drops_only_the_allowlists_that_name_a_path_alone(tmp):
    del tmp
    strip = MODULE.strip_path_allowlists
    assert tomllib.loads(strip(DEFAULT)) == STRIPPED
    for broken in (DEFAULT.replace('[allowlist]', '[other]'),
                   DEFAULT + 'x = """\n[allowlist]\n"""\n',
                   DEFAULT.replace("paths = [\n    '''go", "pathz = [\n    '''go"),
                   DEFAULT + "[[rules]]\nid = 'x'\nallowlists = [{paths = ['y']}]\n"):
        with pytest.raises(MODULE.ConfigError):
            strip(broken)


@pytest.mark.parametrize('text, expected', [
    ('[extend]\nuseDefault = true\n', {'extend': {'path': 'C:\\run "x"\\s.toml'}}),
    ('[Extend]\nUseDefault = true # kept\n[allowlist]\nregexes = ["x"]\n',
     {'Extend': {'path': 'C:\\run "x"\\s.toml'}, 'allowlist': {'regexes': ['x']}}),
    ('[extend]\nuseDefault = false\n', None), ('[allowlist]\nregexes = ["x"]\n', None)])
def test_use_default_alone_is_pointed_at_the_stripped_rules(text, expected):
    rewritten = MODULE.point_at_stripped(text, 'C:\\run "x"\\s.toml')
    assert (tomllib.loads(rewritten) if expected else rewritten) == (expected or text)


@pytest.mark.parametrize('text', [
    '[extend]\nuseDefault = true\nUseDefault = true\n', '[extend]\nuseDefault = true\n[Extend]\n',
    '[extend]\nuseDefault = "true"\n', '[extend]\nuseDefault = true\nPath = ""\n',
    'extend = {useDefault = true}\n', 'extend.useDefault = true\n',
    '[extend]\n"useDefault" = true\n[other]\nuseDefault = true\n',
    'a = """\nuseDefault = true\n"""\n[extend]\nuseDefault = true\n',
    'a = """\nuseDefault = true\n"""\n[extend]\n"useDefault" = true\n'])
def test_a_use_default_rewrite_it_cannot_prove_refuses(text):
    with pytest.raises((MODULE.ConfigError, tomllib.TOMLDecodeError)):
        MODULE.point_at_stripped(text, '/stripped.toml')


def test_the_module_writes_both_configs_or_exits_naming_the_refusal(tmp):
    default, stripped, trusted = (Path(tmp) / name for name in ('d.toml', 's.toml', 't.toml'))
    default.write_text(DEFAULT, encoding='utf-8', newline='\n')
    trusted.write_text('[extend]\nuseDefault = true\n', encoding='utf-8', newline='\n')
    MODULE.main([str(default), str(stripped), str(trusted)])
    assert tomllib.loads(stripped.read_text(encoding='utf-8')) == STRIPPED
    assert tomllib.loads(trusted.read_text(encoding='utf-8')) == {
        'extend': {'path': os.path.abspath(stripped)}}
    default.write_text('[other]\n', encoding='utf-8')  # refused too, but after the trusted file
    trusted.write_text('[extend]\nuseDefault = true\nPath = "x"\n', encoding='utf-8', newline='\n')
    with pytest.raises(SystemExit, match=r'sets \[extend\] path'):
        MODULE.main([str(default), str(stripped), str(trusted)])
    assert trusted.read_text(encoding='utf-8') == '[extend]\nuseDefault = true\nPath = "x"\n'
