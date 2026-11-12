# 仅自建临时合成目录示例

下面是人工编制的演示，不扫描真实 home、不访问浏览器资料或凭据。`ROOT` 只表示你准备的发布副本绝对目录；**不是扫描根**。请人工替换示例中的 `/absolute/path/to/mac-cleaner-skill`，不要改成真实 home。

示例使用 Python 3.12 标准库。`tempfile` 在 macOS 的路径通常从 `/var` 开始，而 `/var` 是符号链接，所以仅对**新建的临时路径**调用 `resolve()` 得到 `/private/var/...`。扫描器本身不靠 resolve 绕过链接检查。

```python
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path("/absolute/path/to/mac-cleaner-skill")  # 手工填写发布副本
script = ROOT / "scripts" / "scan_mac.py"
assert script.is_file()

# 全部是本示例新建的路径；不查询 Path.home()。
base = Path(tempfile.mkdtemp(prefix="mac-cleaner-demo-")).resolve()
os.chmod(base, 0o700)
synthetic = base / "synthetic-home"
reports = base / "reports"
cwd = base / "cwd"
isolated_home = base / "isolated-home"
for directory in (synthetic, reports, cwd, isolated_home):
    directory.mkdir(mode=0o700)
for name in ("Downloads", "Desktop", "Documents"):
    (synthetic / name).mkdir()
(synthetic / "Desktop" / ".DS_Store").write_bytes(b"synthetic metadata")
(synthetic / "Downloads" / "copy-a.bin").write_bytes(b"demo" * 400)
(synthetic / "Documents" / "copy-b.bin").write_bytes(b"demo" * 400)

env = {"HOME": str(isolated_home), "TMPDIR": str(base),
       "PATH": os.environ.get("PATH", "")}
command = [sys.executable, "-I", "-B", str(script), "--home", str(synthetic)]

# 这次只许可元信息扫描：duplicate_files 应为 not_run；不生成文件。
result = subprocess.run(command, cwd=cwd, env=env, text=True,
                        capture_output=True, timeout=30)
print(result.stdout)
print("metadata exit", result.returncode)

# 另一次明确许可：只对上面自建的文件读取正文，并保存新 JSON。
result = subprocess.run(command + ["--hash-duplicates", "--output",
                                  str(reports / "new-report.json")],
                        cwd=cwd, env=env, text=True, capture_output=True,
                        timeout=30)
print(result.stdout)
print("hash exit", result.returncode)
print("Synthetic resources retained for inspection:", base)
```

这里的 `timeout=30` 只是演示驱动的超时保护，不是扫描耗时保证。预期有一组 SHA-256 相同的疑似重复项；缺失的 Library/Pictures 等可选根为 `not_present`，不应冒充“真实机器没有候选”。不产生删除建议。

目录和报告保留供检查，脚本不清理它们。请只手工处理本示例创建的资源，不使用泛化清理命令。报告在新建私有目录内，JSON 权限应为 0600；重用同一文件名会失败退出 2。

## 从源码外运行测试

在同样新建的 `base/cwd` 和 `isolated-home` 环境中，可以替换上面 `command` 为

```python
command = [sys.executable, "-I", "-B", str(ROOT / "tests" / "test_scan_mac.py"), "-v"]
```

用 `os.open(base / "tests.log", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)` 新建私有日志，将测试 stdout/stderr 指向该 FD。不要把日志或 JSON 保存到发布目录。测试使用小阈值、合成文件和一个 100 MiB 稀疏边界文件；不读取历史固定报告路径。真实宿主 Skill 的模型行为仍需另行授权验证。
