"""Helpers the suites share: Git Bash lookup, workflow parsing, shipped-pin reading."""
import os
import shutil
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _action_bash(*, windows=None, environment=None):
    environment = os.environ if environment is None else environment
    windows = os.name == 'nt' if windows is None else windows
    path = environment.get('PATH', '')
    if not windows:
        bash = shutil.which('bash', path=path)
        if bash is None:
            raise RuntimeError('Bash was not found on PATH for action tests')
        return bash

    # Actions uses Git for Windows for `shell: bash`. A plain Windows PATH
    # lookup can instead select System32's WSL shim, which is a different shell.
    roots = []
    git = shutil.which('git.exe', path=path)
    if git is not None:
        directory = Path(git).resolve().parent
        if directory.name.casefold() in ('cmd', 'bin'):
            root = directory.parent
            if root.name.casefold() in ('mingw32', 'mingw64'):
                root = root.parent
            roots.append(root)
    for key in ('ProgramFiles', 'ProgramW6432', 'ProgramFiles(x86)'):
        if environment.get(key):
            roots.append(Path(environment[key]) / 'Git')
    if environment.get('LOCALAPPDATA'):
        roots.append(Path(environment['LOCALAPPDATA']) / 'Programs' / 'Git')
    for root in roots:
        for relative in ('bin/bash.exe', 'usr/bin/bash.exe'):
            bash = root / relative
            if bash.is_file():
                return str(bash)
    raise RuntimeError('Git for Windows Bash was not found; '
                       'install Git for Windows for action tests')


def _workflow(name):
    path = ROOT / '.github/workflows' / name
    assert path.is_file(), f'missing workflow: {name}'
    return yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)


def _shipped_action_pin(action):
    """Return the one revision every shipped workflow pins ``action`` at.

    The workflows are the source of truth for which release is in use, so a
    dependency upgrade edits YAML only; these tests check that the pins agree
    and are immutable, not which commit they name.
    """
    pins = set()
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        for job in _workflow(path.name)['jobs'].values():
            for step in job.get('steps', []):
                if step.get('uses', '').startswith(action + '@'):
                    pins.add(step['uses'].split('@', 1)[1])
    assert len(pins) == 1, (
        f'{action} must be pinned at exactly one revision across the '
        f'workflows, not {sorted(pins)}')
    return pins.pop()


def _named_run(steps, name):
    runs = [step['run'] for step in steps if step.get('name') == name]
    assert len(runs) == 1, f'expected exactly one step named {name!r}'
    return runs[0]
