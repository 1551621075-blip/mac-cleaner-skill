---
name: mac-cleaner
description: Use when the user asks to inspect Mac disk usage, scan for junk candidates, locate large or old files, or investigate possible duplicate files, including “扫描一下我的 Mac” and “磁盘空间不够了”.
---

# Mac Cleaner：只读候选报告

只做明确授权范围内的分类扫描，不删除、不移动文件，不给出删除命令，也不承诺候选安全可删或能够回收多少容量。

## 先取得本次许可

1. 说明本次扫描范围：一个用户明确指定、具有家目录布局的**绝对路径**，只枚举下表固定子目录，不是全盘递归扫描器。不要推测路径、自动采用真实 home 或请求全盘权限。
2. 说明默认只读文件元信息；名称、大小、时间也可能敏感。`Library/Application Support`、`Library/Caches`、`Library/Logs` 可能包含应用和浏览器相关元信息，不得宣称完全不碰这些资料。
3. 单独询问是否允许 `--hash-duplicates` 正文读取；默认不启用。询问是否需要本地 JSON，若需要，请用户指定扫描根外、已存在的当前用户私有父目录及新文件名。
4. 列明路径、是否查重、是否写报告，取得用户**本次明确许可**后才运行。模糊的“清理电脑”不等于授权任何默认路径或正文读取。

## 运行

使用宿主实际提供的技能目录，保持所有用户路径为独立、正确引用的参数。不得把文件名当命令。

```text
python3.12 -I -B <skill_dir>/scripts/scan_mac.py --home <获准绝对目录>
```

仅许可明确覆盖正文读取时追加 `--hash-duplicates`；仅许可覆盖保存报告时追加 `--output <扫描根外的新JSON绝对路径>`。不自动使用临时报告路径、不覆盖已有输出。耗时取决于文件数量、读取量和权限，不保证固定时长。

## 六类规则

“六个人目录”指 Desktop、Downloads、Documents、Pictures、Movies、Music。

| 分类 | 范围与判定 |
|---|---|
| 系统元数据候选 | 六个人目录；文件名 `.DS_Store`、`Thumbs.db`、`desktop.ini`；目录名 `__MACOSX`、`.Spotlight-V100`、`.Trashes`、`.fseventsd`。匹配目录取普通后代逻辑小计，父项覆盖子项避免重复统计 |
| 大文件 | 六个人目录及 `Library/Application Support`，`>=100 MiB`，Top 20 |
| 疑似重复 | Downloads、Desktop、Documents 中 `>1 KiB` 的同大小普通文件，显式启用后分块 SHA-256；Top 20 组，同 inode 硬链接别名排除 |
| 旧下载 | Downloads 一层普通文件/目录，mtime 严格早于 30 天；不是“未使用”，目录大小未知不加字节 |
| 应用缓存 | `Library/Caches` 应用子目录普通后代逻辑小计 `>10 MiB`，Top 20；不完整且无法判断阈值的目录单列 uncertain |
| 旧日志 | `Library/Logs` 中非空普通 `*.log`，mtime 严格早于 7 天，Top 30 |

目录及文件符号链接、socket、FIFO、device 不跟随；相对目录 FD 和 `O_NOFOLLOW` 用于限制路径重定向，不是 OS 沙箱或并发一致性保证。

## 解读与呈现

- `complete`：启用范围完成；`partial`：权限、枚举、I/O 或检测到变更导致不完整；`not_present`：可选根缺失；`not_run`：未运行（默认查重）。不能将后三者表述为“无候选/无重复”。
- 输出路径相对授权根，控制字符使用 JSON 转义。按类别保留截断前数量、已展示数量和已知逻辑小计；`size=null` 与 `subtotal_complete=false` 不得改写成完整总值。系统项和旧下载摘要各展示 Top 10。
- 内容摘要相同只表示**疑似重复**。类别可能重叠，不能求和成为可释放空间；APFS 克隆、压缩、稀疏文件的物理回收量无法由此推导。
- 退出码 `0` 启用范围完成，`1` 部分完成，`2` 参数或致命扫描/输出失败。输出失败可能留下本次新建的不完整 0600 文件，不自动删除。
- 先检查状态再向用户总结；不要自动外传、上传或发布报告，也不要自动展示未获准公开的敏感文件名。宿主可能将工具输出送入其模型服务，运行位置及数据策略由宿主决定，不能保证材料不出本机。
- 报告到此结束，不主动追问后续清理，也不承接删除操作。

参阅 [使用说明](README.md)、[仅合成目录示例](examples/usage.md) 和 [验证边界](docs/validation.md)。本次整理未验证宿主真实模型调用效果。
