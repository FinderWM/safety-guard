"""bash-sensitive-path-scan：全文兜底扫描。

这些形态的共同点是敏感路径不在 AST 可见的 argv 里 —— 藏在解释器内联载荷或
heredoc 正文中。任何依赖 cmd.args 的规则都看不到，只有全文扫描能抓。

安全：全部只调用分析器，不执行命令；标的一律用不存在的假路径。
"""
from __future__ import annotations

from pathlib import Path

import pytest

RULE = "bash-sensitive-path-scan"

FH = "/tmp/sg-probe/fakehome"  # 不存在的假家目录

# AST 看不见的载荷形态：字面量藏在 -c / -e 的字符串参数里
INLINE_PAYLOAD = [
    f"python3 -c \"open('{FH}/.ssh/id_rsa').read()\"",
    f"node -e \"require('fs').readFileSync('{FH}/.ssh/id_ed25519')\"",
    f"perl -e 'open(F,\"<{FH}/.ssh/id_dsa\")'",
    f"ruby -e 'File.read(\"{FH}/.aws/credentials\")'",
    f"php -r \"echo file_get_contents('{FH}/.netrc');\"",
]

# heredoc 正文：bashlex 把正文当分隔符吞掉，命令列表里只剩无害的解释器名
HEREDOC = [
    f"python3 - <<'PY'\nopen('{FH}/.ssh/id_rsa').read()\nPY",
    f"bash <<'SH'\ncat {FH}/.aws/credentials\nSH",
    f"cat <<EOF > ./notes\n{FH}/.gnupg/secring.gpg\nEOF",
]

# 各类凭据位置，直接出现在 argv 也应命中（与其他规则叠加，不冲突）
CREDENTIAL_PATHS = [
    f"tar -czf ./b.tgz {FH}/.gnupg",
    f"wc -c {FH}/.kube/config",
    f"stat {FH}/.docker/config.json",
    f"file {FH}/.config/gcloud/credentials.db",
    f"wc -l {FH}/.npmrc",
    f"openssl rsa -in {FH}/server.pem -text",
    f"keytool -list -keystore {FH}/app.jks",
]


@pytest.mark.parametrize("cmd", INLINE_PAYLOAD + HEREDOC + CREDENTIAL_PATHS)
def test_sensitive_literal_asks(bash, cwd: Path, cmd: str):
    decision, reason = bash(cmd, cwd)
    assert decision in ("ask", "deny"), f"{cmd!r} got {decision}"
    assert RULE in (reason or ""), f"{cmd!r} 未命中兜底扫描：{reason}"


def test_private_key_body_in_heredoc(bash, cwd: Path):
    """密钥体本身写进文件 —— 路径无害，内容才是机密。"""
    cmd = (
        "cat <<'EOF' > ./deploy_key\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3Blb\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
        "EOF"
    )
    decision, reason = bash(cmd, cwd)
    assert RULE in (reason or ""), f"密钥体未命中：{reason}"


# 不应命中：正常业务里出现的相近词形
BENIGN = [
    'python3 -c "print(1+1)"',
    "node -e \"console.log('hi')\"",
    "cat ./README.md",
    "rg -n environment ./docs",
    "npm install",
    "git commit -m 'update env parsing'",
    "cat ./.env.example",          # .env.example 不是 .env
    "rg -n 'environment' ./src",   # environment 里的 env 不算
    "ls ./envs",                   # envs 不是 .env
    "cat ./config/settings.py",
    "python3 ./scripts/deploy.py",
    "cat ./package.json",
]


@pytest.mark.parametrize("cmd", BENIGN)
def test_benign_not_flagged_by_scan(bash, cwd: Path, cmd: str):
    decision, reason = bash(cmd, cwd)
    assert RULE not in (reason or ""), f"{cmd!r} 误报：{reason}"


def test_scan_survives_parse_failure(bash, cwd: Path):
    """扫描不依赖 AST：parse 失败时仍须生效，否则语法糖就是绕过口。"""
    decision, reason = bash(f"cat {FH}/.ssh/id_rsa 2>&1 |& tee (((", cwd)
    assert decision in ("ask", "deny"), f"got {decision} ({reason})"
