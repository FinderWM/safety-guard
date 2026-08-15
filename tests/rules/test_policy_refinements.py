"""规则降噪、补漏与 symlink 组件检查的回归。"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from safety_guard import context, engine
from safety_guard.config import load as load_config
from safety_guard.contracts import NormalizedRequest, Operation
from safety_guard.rules.file_critical_path_write import FileCriticalPathWrite
from safety_guard.rules.file_external_upload import FileExternalUpload
from safety_guard.rules.file_symlink_write import FileSymlinkWrite


@pytest.mark.parametrize(
    "template",
    [
        "cp -t {destination} {source}",
        "cp --target-directory={destination} {source}",
        "cp -vt{destination} {source}",
        "cp -t {destination} -- {source}",
        "mv -t {destination} {source}",
    ],
)
def test_cp_mv_target_directory_detects_nested_overwrite(
    bash,
    cwd: Path,
    template: str,
):
    source = cwd / "source.txt"
    destination = cwd / "destination"
    source.write_text("source", encoding="utf-8")
    destination.mkdir()
    (destination / source.name).write_text("existing", encoding="utf-8")
    command = template.format(source=source, destination=destination)

    decision, reason = bash(command, cwd)

    assert decision == "ask"
    assert "bash-cp-mv-overwrite-existing" in (reason or "")


def test_cp_into_directory_without_existing_nested_target_allows(bash, cwd: Path):
    source = cwd / "source.txt"
    destination = cwd / "destination"
    source.write_text("source", encoding="utf-8")
    destination.mkdir()

    decision, reason = bash(f"cp -t {destination} {source}", cwd)

    assert decision == "allow", reason


@pytest.mark.parametrize(
    "template",
    [
        "cp -n {source} {destination}",
        "cp -vn {source} {destination}",
        "cp --no-clobber {source} {destination}",
        "mv -n {source} {destination}",
        "mv -vn {source} {destination}",
        "mv --no-clobber {source} {destination}",
    ],
)
def test_cp_mv_no_clobber_does_not_report_overwrite(
    bash,
    cwd: Path,
    template: str,
):
    source = cwd / "source.txt"
    destination = cwd / "destination.txt"
    source.write_text("source", encoding="utf-8")
    destination.write_text("existing", encoding="utf-8")

    decision, reason = bash(template.format(source=source, destination=destination), cwd)

    assert "bash-cp-mv-overwrite-existing" not in (reason or "")
    assert decision == "allow", reason


def test_redirect_target_uses_folded_path(bash, cwd: Path):
    (cwd / "existing.txt").write_text("existing", encoding="utf-8")

    decision, reason = bash('TARGET=existing.txt; echo value > "$TARGET"', cwd)

    assert decision == "ask"
    assert "bash-redirect-overwrite-existing" in (reason or "")


def test_trusted_library_search_path_asks_instead_of_denies(bash, cwd: Path):
    decision, reason = bash("LD_LIBRARY_PATH=/usr/lib ls", cwd)
    assert decision == "ask"
    assert "bash-env-subversion" in (reason or "")


def test_untrusted_library_search_path_still_denies(bash, cwd: Path):
    decision, reason = bash("LD_LIBRARY_PATH=/synthetic-untrusted/lib ls", cwd)
    assert decision == "deny"
    assert "bash-env-subversion" in (reason or "")


@pytest.mark.parametrize(
    "command",
    [
        "env PATH=/tmp/synthetic echo hi",
        "env PATH=/tmp/synthetic true",
        "PATH=/tmp/synthetic /bin/echo hi",
        "PATH=/usr/bin:/bin: echo hi",
        "LD_PRELOAD=/tmp/synthetic.so /bin/echo hi",
    ],
)
def test_env_wrapper_and_empty_path_components_do_not_bypass_subversion(
    bash,
    cwd: Path,
    command: str,
):
    decision, reason = bash(command, cwd)
    assert decision == "deny", reason
    assert "bash-env-subversion" in (reason or "")


def test_first_symlink_finds_intermediate_component_without_real_link(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    link = cwd / "link"
    target = link / "nested" / "file.txt"
    disk = context.DiskStat()
    monkeypatch.setattr(disk, "is_symlink", lambda path: path == link)

    assert disk.first_symlink(target, root=cwd) == link


def test_first_symlink_does_not_treat_cwd_root_as_target_component(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    disk = context.DiskStat()
    monkeypatch.setattr(disk, "is_symlink", lambda path: path == cwd)

    assert disk.first_symlink(cwd / "file.txt", root=cwd) is None


def test_first_symlink_checks_external_intermediate_components(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    link = Path("/synthetic-safety-guard/link")
    target = link / "nested" / "file.txt"
    disk = context.DiskStat()
    monkeypatch.setattr(disk, "is_symlink", lambda path: path == link)

    assert disk.first_symlink(target, root=cwd) == link


def test_file_symlink_write_matches_mocked_intermediate_component(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    target = cwd / "link" / "file.txt"
    ctx = context.build(Operation("Write", {"file_path": str(target)}), str(cwd), load_config())
    monkeypatch.setattr(ctx.disk, "is_symlink", lambda path: path == cwd / "link")

    match = FileSymlinkWrite().match(ctx)

    assert match is not None
    assert match.severity == "medium"


def test_external_upload_follows_mocked_symlink_outside_cwd(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    target = cwd / "linked.txt"
    outside = Path("/synthetic-outside/upload.txt")
    operation = Operation(
        "Read",
        {
            "file_path": str(target),
            "external_upload": True,
            "source_tool": "mcp__synthetic__upload",
        },
    )
    ctx = context.build(operation, str(cwd), load_config())
    monkeypatch.setattr(ctx.disk, "first_symlink", lambda path, root=None: target)
    original_resolve = Path.resolve

    def fake_resolve(path: Path, strict: bool = False) -> Path:
        if path == target:
            return outside
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", fake_resolve)
    match = FileExternalUpload().match(ctx)

    assert match is not None
    assert match.severity == "high"
    assert match.extra["actual_outside"] is True


def test_external_upload_symlink_resolution_failure_denies(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    target = cwd / "linked.txt"
    operation = Operation(
        "Read",
        {
            "file_path": str(target),
            "external_upload": True,
            "source_tool": "mcp__synthetic__upload",
        },
    )
    ctx = context.build(operation, str(cwd), load_config())
    monkeypatch.setattr(ctx.disk, "first_symlink", lambda path, root=None: target)

    def fail_resolve(path: Path, strict: bool = False) -> Path:
        raise RuntimeError("synthetic symlink loop")

    monkeypatch.setattr(Path, "resolve", fail_resolve)

    match = FileExternalUpload().match(ctx)

    assert match is not None
    assert match.severity == "high"
    assert match.extra["resolution_failed"] is True


def test_critical_path_rule_follows_mocked_intermediate_symlink(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    target = cwd / "link" / "config.toml"
    critical = Path("/synthetic-critical/config.toml")
    cfg = replace(load_config(), critical_paths=(critical,))
    ctx = context.build(Operation("Write", {"file_path": str(target)}), str(cwd), cfg)
    monkeypatch.setattr(ctx.disk, "is_symlink", lambda path: path == cwd / "link")
    original_resolve = Path.resolve

    def fake_resolve(path: Path, strict: bool = False) -> Path:
        if path == target:
            return critical
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", fake_resolve)

    match = FileCriticalPathWrite().match(ctx)

    assert match is not None
    assert match.severity == "medium"


def test_critical_path_write_requires_confirmation(cwd: Path):
    target = cwd / "protected.json"
    cfg = replace(load_config(), critical_paths=(target,), fail_open=False)
    request = NormalizedRequest(
        adapter="claude",
        event="PreToolUse",
        tool="Edit",
        operations=(Operation("Edit", {"file_path": str(target)}),),
        cwd=str(cwd),
        audit_input=str(target),
    )

    result = engine.evaluate(request, cfg)

    assert result.decision == "ask"
    assert "file-critical-path-write" in (result.reason or "")


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("bash", "ask"),
        ("bash -lc 'echo synthetic'", "allow"),
        ("kubectl delete namespace synthetic", "ask"),
        ("kubectl delete namespace/synthetic", "ask"),
        ("kubectl delete pod namespace", "allow"),
        ("kubectl delete --namespace synthetic pod namespace", "allow"),
        ("kubectl delete namespace --help", "allow"),
        ("kubectl delete namespace synthetic --dry-run=client", "allow"),
        ("kubectl delete namespace synthetic --dry-run server", "allow"),
        ("kubectl delete namespace synthetic --dry-run=none", "ask"),
        ("kubectl delete --dry-run none namespace synthetic", "ask"),
        ("terraform destroy", "ask"),
        ("terraform destroy -help", "allow"),
        ("psql -c 'DROP TABLE synthetic_table'", "ask"),
    ],
)
def test_new_medium_rules_only_match_real_actions(bash, cwd: Path, command: str, expected: str):
    decision, reason = bash(command, cwd)
    assert decision == expected, reason


@pytest.mark.parametrize(
    "command",
    [
        (
            "python3 -c \"from subprocess import run as invoke; "
            "command = ['id']; invoke(command)\""
        ),
    ],
)
def test_dynamic_python_subprocess_forms_still_deny(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "deny"
    assert "bash-interpreter-shell-escape" in (reason or "")


@pytest.mark.parametrize(
    "command",
    [
        "python3 -c \"import subprocess; subprocess.call(['id'])\"",
        "python3 -c \"from subprocess import *; call(['id'])\"",
        "python3 -c \"import subprocess; invoke = subprocess.run; invoke(['id'])\"",
        (
            "python3 -c \"import subprocess; "
            "subprocess.run(['git', 'diff', '--output=./synthetic.out'])\""
        ),
    ],
)
def test_fixed_python_subprocess_forms_require_confirmation(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "ask"
    assert "bash-interpreter-shell-escape" in (reason or "")


def test_fixed_read_only_python_subprocess_is_not_shell_escape(bash, cwd: Path):
    command = "python3 -c \"import subprocess; subprocess.run(['git', 'status', '--short'])\""
    decision, reason = bash(command, cwd)
    assert decision == "allow", reason


@pytest.mark.parametrize(
    "argv",
    [
        "['git', '--help']",
        "['git', '--version']",
        "['git', '-C', '.', '--help']",
    ],
)
def test_python_subprocess_git_information_commands_allow(
    bash,
    cwd: Path,
    argv: str,
):
    command = f'python3 -c "import subprocess; subprocess.run({argv})"'
    decision, reason = bash(command, cwd)
    assert decision == "allow", reason


def test_python_subprocess_cwd_override_requires_confirmation(bash, cwd: Path):
    command = (
        "python3 -c \"import subprocess; "
        "subprocess.run(['git', 'status'], cwd='/synthetic-review-cwd')\""
    )
    decision, reason = bash(command, cwd)
    assert decision == "ask", reason
    assert "bash-interpreter-shell-escape" in (reason or "")


@pytest.mark.parametrize(
    "payload",
    [
        "print(subprocess.PIPE)",
        "print(subprocess.list2cmdline(['git', 'status']))",
    ],
)
def test_non_executing_subprocess_helpers_are_not_intercepted(
    bash,
    cwd: Path,
    payload: str,
):
    command = f'python3 -c "import subprocess; {payload}"'
    decision, reason = bash(command, cwd)
    assert decision == "allow", reason


@pytest.mark.parametrize(
    "payload",
    [
        "subprocess.run(['ls', './synthetic-path'])",
        "subprocess.run(['git', 'status', '--short', './synthetic-path'])",
    ],
)
def test_fixed_read_only_python_subprocess_accepts_path_operands(
    bash,
    cwd: Path,
    payload: str,
):
    command = f'python3 -c "import subprocess; {payload}"'
    decision, reason = bash(command, cwd)
    assert decision == "allow", reason


@pytest.mark.parametrize(
    "command",
    [
        "deno run --config ./deno.json /synthetic-outside/app.ts",
        "bun run --preload ./setup.ts /synthetic-outside/app.ts",
    ],
)
def test_deno_bun_value_options_do_not_hide_outside_script(
    bash,
    cwd: Path,
    command: str,
):
    decision, reason = bash(command, cwd)
    assert decision == "ask", reason
    assert "bash-outside-script-exec" in (reason or "")


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("git commit -m push", "allow"),
        ("git commit -m push --force", "allow"),
        ("git --help push", "allow"),
        ("git -C . push --dry-run origin main", "allow"),
        ("git push --dry-run --force origin main", "allow"),
        ("git push -nf origin main", "allow"),
        ("git push --push-option --dry-run --force origin main", "deny"),
        ("git push origin feature/new", "ask"),
        ("git push --force origin", "deny"),
        ("git push --force origin feature/new", "ask"),
        ("git push --force --repo origin feature/new", "ask"),
        ("git push --force --repo=origin feature/new", "ask"),
        ("git push -o force-if-includes origin feature/new", "ask"),
        ("git push --push-option=force-if-includes origin feature/new", "ask"),
        ("git push -o --delete origin feature/new", "ask"),
        ("git push --push-option=--delete origin feature/new", "ask"),
        ("git push -o --mirror origin feature/new", "ask"),
        ("git push --push-option=--mirror origin feature/new", "ask"),
        ("git push --force-with-lease=main origin main", "deny"),
        ("git push --force origin main feature/new", "deny"),
        ("git push --force origin feature/new main", "deny"),
        ("git push --mirror origin", "deny"),
        ("kubectl exec pod -- delete namespace", "allow"),
        ("kubectl --namespace synthetic delete namespace synthetic", "ask"),
        ("kubectl delete namespaces.v1 synthetic", "ask"),
        ("kubectl delete -f namespace.yaml", "allow"),
        ("terraform workspace select destroy", "allow"),
        ("terraform -chdir=synthetic destroy", "ask"),
        ("bash -i", "ask"),
        ("bash -s script-name", "ask"),
        ("bash -O extglob", "ask"),
        ("bash -O extglob script-name", "allow"),
        ("bash script-name", "allow"),
        ("cat ./payload | python3 -c 'print(1)' -m json.tool", "allow"),
        ("cat ./payload | python3 -c 'print(1)'", "allow"),
        ("cat ./payload | python3 ./script.py", "allow"),
        ("cat ./payload | bash ./script.sh", "allow"),
        ("cat ./payload | busybox sh ./script.sh", "allow"),
    ],
)
def test_command_rules_use_actual_subcommands(bash, cwd: Path, command: str, expected: str):
    decision, reason = bash(command, cwd)
    assert decision == expected, reason


@pytest.mark.parametrize(
    "command",
    [
        'git push --force origin "$SYNTHETIC_BRANCH"',
        'git push --delete origin "$SYNTHETIC_BRANCH"',
        "git push --force origin HEAD",
    ],
)
def test_force_or_delete_with_unresolved_destination_denies(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)

    assert decision == "deny", reason
    assert "bash-git-push-force-protected" in (reason or "")


def test_folded_non_protected_force_destination_still_asks(bash, cwd: Path):
    decision, reason = bash("B=feature/synthetic; git push --force origin $B", cwd)

    assert decision == "ask", reason
    assert "bash-git-push" in (reason or "")


@pytest.mark.parametrize(
    "command",
    [
        "python3 -c \"import subprocess; flag = False; subprocess.run(['git', 'status'], shell=flag)\"",
        "python3 -c \"import subprocess; subprocess.run(['git', 'status'], executable='/synthetic/bin/git')\"",
        "python3 -c \"import subprocess; options = {}; subprocess.run(['git', 'status'], **options)\"",
    ],
)
def test_subprocess_execution_overrides_are_not_allowlisted(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "deny"
    assert "bash-interpreter-shell-escape" in (reason or "")


def test_high_subprocess_form_wins_over_fixed_reviewable_call(bash, cwd: Path):
    command = (
        "python3 -c \"import subprocess; subprocess.run(['id']); "
        "options = {}; subprocess.run(['git', 'status'], **options)\""
    )
    decision, reason = bash(command, cwd)
    assert decision == "deny"
    assert "bash-interpreter-shell-escape" in (reason or "")


def test_subprocess_literal_shell_false_remains_allowlisted(bash, cwd: Path):
    command = "python3 -c \"import subprocess; subprocess.run(['git', 'status'], shell=False)\""
    decision, reason = bash(command, cwd)
    assert decision == "allow", reason


def test_python_git_diff_textconv_is_not_allowlisted(bash, cwd: Path):
    command = "python3 -c \"import subprocess; subprocess.run(['git', 'diff', '--textconv'])\""
    decision, reason = bash(command, cwd)
    assert decision == "deny"
    assert "bash-interpreter-shell-escape" in (reason or "")


@pytest.mark.parametrize("command", ["git clean -n", "git clean -ndx", "git clean --dry-run -fdx"])
def test_git_clean_dry_run_is_non_destructive(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "allow", reason


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("note.txt", "ask"),
        ("id_ed25519.pub", "ask"),
        (".ssh/id_ed25519.pub", "ask"),
        ("id_ed25519", "deny"),
        (".env", "deny"),
        (".env.staging", "deny"),
        (".env.example", "ask"),
        (".npmrc", "deny"),
        (".netrc", "deny"),
        ("/synthetic-outside/note.txt", "deny"),
    ],
)
def test_external_upload_only_hard_denies_sensitive_or_external_paths(
    cwd: Path,
    path: str,
    expected: str,
):
    cfg = replace(load_config(), fail_open=False)
    request = NormalizedRequest(
        adapter="codex-pretool",
        event="PreToolUse",
        tool="mcp__chrome_devtools__upload_file",
        operations=(
            Operation(
                "Read",
                {
                    "file_path": path,
                    "external_upload": True,
                    "source_tool": "mcp__chrome_devtools__upload_file",
                },
            ),
        ),
        cwd=str(cwd),
        audit_input=path,
    )

    result = engine.evaluate(request, cfg)

    assert result.decision == expected
    assert "file-external-upload" in (result.reason or "")


def test_rule_internal_error_cannot_be_downgraded(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    class BrokenRule:
        id = "synthetic-broken-rule"

        def match(self, ctx):
            raise RuntimeError("synthetic failure")

    monkeypatch.setattr(engine, "iter_rules_for_tool", lambda tool, disabled=(): (BrokenRule(),))
    cfg = replace(
        load_config(),
        fail_open=False,
        severity_overrides={"synthetic-broken-rule": "medium"},
    )
    request = NormalizedRequest(
        adapter="claude",
        event="PreToolUse",
        tool="Bash",
        operations=(Operation("Bash", {"command": "echo synthetic"}),),
        cwd=str(cwd),
        audit_input="echo synthetic",
    )

    result = engine.evaluate(request, cfg)

    assert result.decision == "deny"


def test_rule_internal_error_honors_fail_open(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    class BrokenRule:
        id = "synthetic-broken-rule"

        def match(self, ctx):
            raise RuntimeError("synthetic failure")

    monkeypatch.setattr(engine, "iter_rules_for_tool", lambda tool, disabled=(): (BrokenRule(),))
    request = NormalizedRequest(
        adapter="claude",
        event="PreToolUse",
        tool="Bash",
        operations=(Operation("Bash", {"command": "echo synthetic"}),),
        cwd=str(cwd),
        audit_input="echo synthetic",
    )

    result = engine.evaluate(request, replace(load_config(), fail_open=True))

    assert result.decision == "allow"
