# 测量方法

[English](measurement.md) | 简体中文

## 复现

### 三种发布配置

在项目根目录、已选定的 Python 环境中运行：

```bash
# 自动探测 Clang 及匹配的 opt，仅比较三个配置。
python tools/measure.py

# 等价的统一入口，可显式设置参数。
python tools/anti_rea.py measure --jobs 8 --samples 15 --out build/three-release

# 指定工具链。保留 clang++ 驱动名称，不要替换为 clang 符号链接的目标。
python tools/measure.py --compiler /path/to/llvm/bin/clang++ \
  --opt /path/to/llvm/bin/opt --jobs 8 --samples 9

# 仅从已有报告重新生成差异，不编译、不执行。
python tools/measure.py --report-only build/measurement.json --out build/review
```

默认配置为 `baseline`、`stripped`、`protected`，无需 xollvm。先检查本地
`build/toolchains/xollvm23/bin/clang++`，再检查 PATH 上的 Clang。编译器与优化器的
LLVM 主版本必须一致；显式指定的工具链不会被悄悄替换。此入口已在 Linux 验证，
Windows 仍需按 [Windows 指南](windows.zh-CN.md)执行平台验收。

默认八个构建任务，每种负载九次采样。每次均全新构建，避免用缓存构建对比全新构建。
请在空闲机器运行，避免多个测量共用构建目录。编译、测试失败或比较不完整均返回非零；
工具不会自动安装依赖。

| 默认输出 | 内容 |
| --- | --- |
| `build/measurement.md` | 配置状态和测量值 |
| `build/measurement.json` | 样本统计、哈希、审计结果及产物位置 |
| `build/measurement-differences.md` | 可读的两两绝对差和百分比 |
| `build/measurement-differences.json` | 机器可读差异 |
| `build/measurement-<profile>.log` | 配置、构建、测试和安装日志 |

`--out` 是报告**前缀**，不是目录；相对值始终以项目根目录为基准。
显式工具路径和 `--report-only` 输入则以调用者工作目录为基准。同前缀报告会被覆盖。
构建及安装使用项目内按编译器区分的目录，完整报告会记录位置。

差异包括发布字节数、全新构建秒数、启动进程耗时中位数、基准内部耗时中位数和敏感语料命中数。
计算为 `delta = target - reference`、`change = 100 * delta / reference`；参考值为零时显示
`N/A`。比较 stripped/baseline、protected/baseline、protected/stripped。
必需配置缺失或失败时，差异报告明确标为不完整，不输出数值差。样本范围和标准差以原始 JSON 为准。

### 完整矩阵

```bash
python tools/anti_rea.py compare \
  --compiler /path/to/xollvm/bin/clang++ \
  --opt /path/to/xollvm/bin/opt --jobs 8 --samples 9 \
  --out build/comparison
```

增加 `--publish docs/comparison` 可生成公开 Markdown 摘要和不含原始审计发现的精简 JSON。
完整清单和命令日志仍在忽略的构建目录；发布前需要审阅公开输出。

发布命令会重新生成英文摘要。替换 `docs/comparison.md` 后，应恢复其语言链接，并根据同一次运行
更新 `docs/comparison.zh-CN.md`，不能将新测量与旧中文数据混用。

矩阵包括 baseline、stripped-only、protected-only、light、medium、heavy 和 mixed VM。
可用 `--presets baseline stripped protected` 缩小范围。所有完成项使用相同编译器、
RelWithDebInfo/O2，不启用 LTO；JSON 记录按编译器区分的构建/安装相对位置。

每项都执行配置、全新构建、测试和安装。编译/链接耗时只测一次，不含配置、测试、安装及依赖准备；
它是一次观测，不是统计意义上的构建性能排名。不会清空操作系统文件缓存。

## 负载和指标

原生 Windows 使用 [Windows 指南](windows.zh-CN.md)中的已验收包测量工具，单独记录 OFF/ON
数据并保留慢样本及离散程度，不复用 Linux 表格；上述 Linux 三配置命令不能替代原生 Windows 数据。

- `startup`：启动新进程，执行一次策略迭代后退出；进程耗时包含加载器及字符串解密启动开销。
- `bench`：执行 500,000 次选定策略迭代，报告内部时间；另测包含进程开销的总时间。
- `selftest`：验证跨库 RTTI、自定义异常、热循环输出精确一致及条件单次求值。
- `resource`：相对可执行文件加载系数，也验证复制到新位置后的运行。
- 安装体积：可执行文件加示例共享库，不含系统运行库、libsodium 和私有开发文件。
- 泄露：显式敏感语料的子串匹配，以及路径、文件名、符号和 RTTI 的更广候选清单。

JSON 给出中位数、最小值、最大值和总体标准差，Markdown 展示中位数。
正式性能研究应在空闲机器记录 CPU 策略并重复实验。WSL 启动数据只是本地观测，不能直接预测原生 Windows。

无符号 32 位运算提供确定行为。脚本计算独立 Python 参考值，不仅要求保护版与基线互相一致；
每个基准样本均须匹配。

## 产物审计

扫描安装副本，而不只扫描构建目录中的主程序。源码扫描只提示泄露位置，不解析 C++ 预处理或证明可达性。
二进制匹配证明字节存在，不证明来源。显式指定名称的精确命中标为 confirmed；疑似路径仍为候选。
公开导入/导出可以既已确认又是有意保留。

默认函数、变量查询列表为空，路径始终扫描。`--allow` 接受由 `pattern` 和非空 `reason` 组成的 JSON 列表；
允许项仍保留证据：

```json
[
  {"pattern": "^\\$ORIGIN$", "reason": "Relocatable ELF loader path"},
  {"pattern": "^ar_create$", "reason": "Documented public C factory"}
]
```

审计器可从 skill 目录独立运行，扫描 ASCII、UTF-16LE、UTF-16BE 可打印字符串。
可选 pyelftools/pefile 提供结构化元数据。解析器缺失或元数据损坏记录为 `not_checked`，不能算通过。
压缩字符串、任意编码、反汇编及完整 DWARF/PDB 变量枚举不在范围内。

## 结果含义

`Passed` 表示构建、测试和声明的敏感文本发布门禁通过，不代表没有可识别字符串。
`Not run` 表示所需工具链/能力不可用；`Failed` 表示已尝试但失败，需检查日志，不能改标为缺工具。

私有 IR、映射和混淆报告有意保留原名。原始 JSON 和日志留在忽略目录；公开摘要移除开发者根路径。
任何原始证据入公开仓库前均须审阅。

## 相对速度与预算门槛

原生 Windows 的 `tools/measure_windows.py` 支持采样前声明启动、策略循环和整包体积预算，
命令见 [Windows 测量指南](windows.zh-CN.md)。超限时保留实测结果并返回非零，功能通过不能覆盖预算失败。

独立保护 skill 的 `scripts/measure.py` 也支持工作负载清单中的可选 `comparisons`：

```json
{"reference": "baseline", "target": "protected", "max_slowdown": 1.25, "max_size_ratio": 2.0}
```

将上述对象放入清单顶层 `comparisons` 数组；两端均须是现有 profile 名称。
配置示例和完整格式见[英文操作参考](protection-skill/references/operations.md)。
轮次间轮换配置顺序，保留每次耗时并在测量后核对声明产物的大小及 SHA-256。
体积门槛必须有明确的两组产物和有效参考大小；失败或缺少参考值不能算预算通过。
相对速度是时间比率的倒数：耗时翻倍意味着保留 50% 速度，不是减去“100% 开销”。
这里的通用测量是进程墙钟时间，不应与 Windows 策略循环的内部耗时混为一谈。
