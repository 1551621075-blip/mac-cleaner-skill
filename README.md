# mac-cleaner-skill

Mac 家目录布局的**只读分类扫描 Skill**：一份宿主指令和一个 Python 3.12 标准库 CLI，不是清理器、完整 Agent、系统沙箱或磁盘回收保证。默认只读元信息，查重正文读取必须单独开启。

作者：**guozizhu**。用户确认本作品为个人原创且有权整理上传。本目录是本地发布整理副本；未选择开源许可、未授予公开再分发许可，不附加 LICENSE。可见源码不等于获得再分发授权。

## 安装到新目标

先确认使用权限。选择宿主实际支持的技能目录，在其中新建 `skills/mac-cleaner/` **空目标**，再将本目录的七个文件按原相对布局复制进去。目标若已存在任何内容或是符号链接，立即停止，先人工比较；不要使用覆盖安装命令。本轮未实际安装、未修改任何已安装技能。

宿主须能发现 `SKILL.md` 并具备用户授权的本地 Python 工具能力。独立 CLI 仅需 Python 3.12 标准库和 macOS 提供的目录 FD、`O_NOFOLLOW` 支持；没有依赖安装、外部命令、网络或模型服务调用。未验证所有宿主兼容性。

## 运行与授权

先阅读 [SKILL.md](SKILL.md)，说明扫描根、九个固定扫描子树、是否读取正文、是否写 JSON，并取得**本次许可**。`--home` 是明确获准且具有 Desktop/Downloads 等布局的绝对目录，不是默认真实 home。拒绝 `/`、相对路径、`.`/`..`/空路径组件以及根或中间符号链接；不要用真实目录试跑本项目示例。

```text
python3.12 -I -B /absolute/skill/scripts/scan_mac.py --help
python3.12 -I -B /absolute/skill/scripts/scan_mac.py --home /absolute/authorized-synthetic-home
python3.12 -I -B /absolute/skill/scripts/scan_mac.py --home /absolute/authorized-synthetic-home --hash-duplicates --output /absolute/private-existing-parent/new-report.json
```

这些是参数形式说明；可实际操作的**自建临时合成树**示例见 [examples/usage.md](examples/usage.md)。不使用 `Path.home()`、`$HOME` 或 `~` 自动推断扫描目标。`--help` 退出 0，缺参不扫描。导入模块无扫描、打印、写文件副作用。公开函数 `scan(home, *, hash_duplicates=False, now=None, thresholds=None)` 返回字典；测试可注入 Unix 秒时钟和阈值，CLI 不额外暴露配置平台。

| 参数 | 契约 |
|---|---|
| `--home PATH` | 必填，绝对、明确、获准的家目录布局根 |
| `--hash-duplicates` | 默认关闭；仅开启时读取查重范围同大小且 `>1 KiB` 候选内容 |
| `--output PATH` | 可选，绝对新 JSON 文件；扫描根外、父目录已存在、由当前有效用户拥有且 mode 无组/其他用户权限；文件创建权限 0600 |

不带 `--output` 只在 stdout 输出分类摘要（每类一条 JSON 转义行）。不自动写 `/tmp`，不创建输出父目录、不覆盖、不删除。输出预检在扫描前进行，扫描后用同一父目录 FD 及 `O_EXCL|O_NOFOLLOW` 独占创建。任何已有目标（含断链）均拒绝。

## 六类范围与准确含义

六个人目录是 Desktop、Downloads、Documents、Pictures、Movies、Music。元信息只共享一次这些子树及下列 Library 三个子树的遍历，不枚举无关 home 子树。

| 类别键 | 规则 | 展示上限 |
|---|---|---|
| `system_junk` | 六个人目录中 `.DS_Store`、`Thumbs.db`、`desktop.ini` 普通文件；`__MACOSX`、`.Spotlight-V100`、`.Trashes`、`.fseventsd` 目录。普通后代逻辑小计，最外层匹配项覆盖子项避免重复计数 | 10 |
| `large_files` | 六个人目录加 `Library/Application Support` 中普通文件 `>=100 MiB` | 20 |
| `duplicate_files` | Downloads/Desktop/Documents 中普通文件 `>1 KiB`，先按大小再 SHA-256 分组；同 inode 硬链接仅一份参与 | 20 组 |
| `old_downloads` | Downloads 直属普通条目，mtime 严格早于 30 天；目录大小未知、不计字节，不递归作为本类候选 | 10 |
| `app_caches` | `Library/Caches` 应用子目录普通后代逻辑大小 `>10 MiB`；不完整且已知值不足以判定阈值时单列 uncertain | 20 |
| `old_logs` | `Library/Logs` 普通非空 `*.log`，mtime 严格早于 7 天 | 30 |

大小使用二进制单位。时间是 UTC Unix 秒差，不代表访问次数或是否仍使用。普通项按已知逻辑大小降序、相同值按相对路径排序；疑似重复组保留原先“文件大小 × (独立 inode 数 − 1)”降序意图，但这个排序值不是回收量。重复组逻辑小计是组内独立 inode 大小之和，不包含硬链接别名。

## 状态和报告契约

顶层含 `schema_version=1`、UTC `generated_at`、`thresholds`、`enabled_categories`、`categories` 和限制说明；无绝对扫描根。

| 状态 | 含义 |
|---|---|
| `complete` | 启用范围的相关扫描完成；规则内跳过链接/特殊文件不算失败 |
| `partial` | 权限、枚举、I/O 或检测到身份/大小/时间变化，结论不完整 |
| `not_present` | 此类可选根均不存在；逐根情况见 `roots` |
| `not_run` | 未启用，默认查重即此状态，绝不是“无重复” |

- `match_count`、`known_logical_bytes` 是**截断前**已判定候选数量及已知逻辑字节小计；`shown_count`、`truncated` 解释展示截断。系统项计数在最外层目录去重后计算。
- `size=null` 表示未知完整大小，已知部分留在 `known_logical_bytes`；`subtotal_complete=false` 不得当作完整总值。旧下载目录可以扫描状态完整但字节小计仍不完整。
- 未能判断阈值或哈希结果的条目进入 `uncertain_count`、`uncertain_items`，另存截断前 `uncertain_known_logical_bytes`，并有 `uncertain_truncated`。未知候选不能解释为不存在候选。
- `error_count`/`errors` 记录相对路径、阶段、错误类型，不回显 OS 原始异常绝对路径；`skip_count`/`skips` 按原因计数。错误清单未截断，报告仍可能较大。
- 部分可选根缺失不导致 partial；可扫描根中的失败会导致 partial。旧下载的候选范围只有一层，深层错误不误作其候选读取失败。
- 退出码：`0` 启用范围完成（允许可选根 `not_present` 和规则内排除），`1` 任一启用类别 `partial`，`2` 无效参数、路径边界拒绝或致命输出失败。写出失败可能留下本次新建的不完整 0600 文件，脚本不自动删除。

## 只读和安全边界

目录通过 FD 相对遍历、逐组件 `O_NOFOLLOW` 打开，跳过目录/文件符号链接、socket、FIFO、device。文件哈希打开后先 `fstat` 确認普通文件身份，再检查读取前后 inode、size、mtime、ctime 及名字关联；变化或读取失败标为未知/partial。默认扫描不打开普通文件正文；开启哈希可能引起 atime 更新，不宣称所有元信息完全不变。

父目录用 FD 固定并反复核对祖先名字/身份，不把一次 `resolve()` 视为安全证明。**并发重命名仍不可能靠 Python 检查完全原子消除**：在最终检查与创建系统调用之间移动父目录，可能在原来固定的目录留下新文件；检测后失败退出、不删除。遇到对抗性并发移动，请在受信任、静止的合成/获准目录中运行。本工具不是 OS 沙箱、无文件系统快照，不保证发现所有并发变更。

私有目录检查看 POSIX 所有者和 mode，未验证所有 macOS ACL/挂载/网络文件系统语义；不应对 ACL 授予额外用户访问的目录保存报告。测试只涵盖本地合成树及故障注入。

## 隐私与容量限制

`Library/Application Support`、`Library/Caches`、`Library/Logs` 包含应用或浏览器相关元信息；**即使不读取正文，文件名、相对路径、大小、时间和摘要也可能敏感**。大日志和缓存名尤其可能含业务标识。报告默认不自动外传；宿主可能把工具输出发送给其模型服务，需另行审阅宿主数据策略，不能由此保证“资料不出本机”。

分类只是候选，不保证都是垃圾、不保证安全删除。各类别互相重叠，不能相加作为“可释放容量”。APFS 克隆、压缩、稀疏文件、硬链接的物理占用与逻辑大小不同，扫描不能推导实际物理回收量，也不提供删除操作。

## 验证

详见 [docs/validation.md](docs/validation.md)。仅标准库 unittest、源码静态检查、隔离 HOME/cwd 的自建合成目录 CLI；无网络、无真实 Mac 家目录扫描、无浏览器/凭据读取、无宿主真实模型效果验收。测试和报告不属于技能有效性的完整证明。
