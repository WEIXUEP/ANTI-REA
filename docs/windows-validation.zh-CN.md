# Windows 原生 demo 验证

[English](windows-validation.md) | 简体中文

原始运行测于 2026-10-16（Asia/Shanghai），使用本仓库 demo，不是 Palace 或旧版独立 RTTI 实现。
完整私有记录在 `build/windows-acceptance/20261016T001110774585Z/result.json`。
本页仅公开脱敏摘要；密钥、映射、IR、PDB、完整审计及二进制留在内部。

## 环境与复现

- Windows x64；clang-cl/opt 23.1.2：`F:/Program_Professional/xollvm-windows-llvm23-Release/bin`。
- Intel oneAPI：`F:/Intel/oneAPI/setvars.bat`；MSVC 14.43.34808，SDK 10.0.22621.0，
  JOM 1.1.7，CMake 3.30，Python 3.12.14。
- 官方 libsodium 1.0.22 MSVC 包，x64/v143/Release/dynamic 导入库、DLL 及头文件；压缩包 SHA-256：
  `3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279`。
- 混淆级别 `NONE`：本次测信息保护与 ABI，不测 xollvm 控制流/VM。

```powershell
python tools/validate_windows.py `
  --llvm-bin F:/Program_Professional/xollvm-windows-llvm23-Release/bin `
  --environment F:/Intel/oneAPI/setvars.bat `
  --sodium-prefix <libsodium-root> `
  --sodium-library <libsodium-root>/x64/Release/v143/dynamic/libsodium.lib `
  --sodium-runtime <libsodium-root>/x64/Release/v143/dynamic/libsodium.dll
```

依赖由操作者提供，runner 不下载编译器或库。开发环境和 Ninja 替代方式见
[Windows 指南](windows.zh-CN.md)。每次使用新证据目录并生成独立密钥。

## 结果

四项均使用 `/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO`。

| 构建 | RTTI/异常检查 | 确认语料命中 | 未执行二进制检查 |
| --- | ---: | ---: | ---: |
| Debug，保护 OFF | 39 通过 | 6 | 0 |
| Debug，保护 ON | 39 通过 | 0 | 0 |
| Release，保护 OFF | 39 通过 | 6 | 0 |
| Release，保护 ON | 39 通过 | 0 | 0 |

正对照语料为三个原始诊断片段及 `ResonantKernel` 精确 raw RTTI 名称。
两个原始构建均检出所有语料；EXE/DLL 共六次精确命中，对应四个唯一条目。

原生套件覆盖 EXE/DLL 独立描述符、跨 TU/DLL 相等与不等、哈希、排序、`type_index` 容器、双向转换、
单/多/虚继承、失败转换、`bad_typeid`、精确/基类及无关异常、重抛、`exception_ptr`、指针异常转换、
const 增加及拒绝不合法转换。

每个保护配置有 43 个唯一 RTTI 条目，其中 19 个受保护、24 个不变。
普通、复合模板、局部和指针类型仅在选择范围内改名；无关类型和模板不变。
运行时名称通过私有映射恢复，恢复 CLI 已执行；映射中所有选定原始 RTTI 名均不再存在于两个保护二进制。

同密钥全新重建保持映射一致。替换共用密钥文件后，无需手动 clean 即触发生成及全部六个 EXE/DLL 对象重编译；
所有选定名称改变，无关名称不变。换钥包再次通过运行、包清单及二进制门禁。

内部 PDB 存在，CodeView 仅含 `anti-rea-demo.pdb`、`engine.pdb` 基名。
七个预期 C 导出均保留；EXE/DLL 不含 master/private 密钥的十六进制文本或原始字节。
暂存包未发现已标记私有文件；复制到其他目录后，从 PATH 移除构建、工具链及依赖前缀，DLL 和资源仍正常加载。

当时 Python 验证共 48 项：47 通过，1 项因符号链接权限跳过。
覆盖短/Unicode 匹配、baseline/范围、私有包、损坏 PE、导入解析错误恢复、只读输出保护及脱离仓库的独立 ZIP 扫描。
skill 格式和 MkDocs 严格检查通过。

## 原生运行发现并修正的问题

- `/EHsc` 默认将 C linkage 入口视为不抛异常，异常入口现显式使用 `noexcept(false)`。
- JOM 将 `%_PDB%` 转义为包含 `%engine.pdb%` 的引用；CMake 改为显式传目标 PDB 基名。
- 本机 LLVM 子集没有 `llvm-undname`；launcher 增加 DbgHelp 回退并识别本地 lambda 函数拼写。
- 两项工具测试曾假定 POSIX 路径，现保留实际平台路径和可执行文件后缀。

## 限制

这些证据仅证明该 demo 在该工具链/CRT 下的行为，不证明 Palace 或任意插件可用。
未验证 LTO、PCH、modules、sanitizers 或混淆/VM；生产者/消费者混用保护模式或密钥不受支持。

扫描器是清单与指定语料门禁，不是零泄露证明。公开导入/导出、继承结构及普通标签仍可见。
密文可能形成疑似路径。私有文件分类按文件名/包路径启发式处理，改名后可能漏检；不解析 PDB 内容。
保护 PDB 保留链接符号，但缺少被 launcher 移除的源元数据。

## REA 静态复核（2026-10-20）

对保留的未保护 Release EXE/DLL 执行了可选 [REA 集成（英文）](skill/references/rea.md)。
这是新增静态复核，未重复上述四配置运行验收。
新 baseline 在两个产物中记录 271 项泄露/元数据发现，结构化元数据无未检查项。SHA-256：

- `anti-rea-demo.exe`：`fff3ce2196d029a09a18ad27537febb2bf56adfe0412e68c9d9d9b86b4ef5f2f`。
- `engine.dll`：`ce24efe2c4a92ccfebd226800800c146c239f1cb40ea4f47fe89704308210ee9`。

计划将 EXE 的 `memcpy`/`memmove` 及 DLL 的 `memcpy` 导入列为复核候选，不是已确认漏洞。
实际查询使用已安装的官方 REA 6.4.0 Windows 包、Ghidra 12.1.4、Node 24.19.0、JDK 24.0.1，
未执行或修改目标。

| 查询 | 观测 |
| --- | --- |
| EXE 搜索 `memcpy` | 外部导入及 thunk `0x14000c199` |
| EXE 对该 thunk 的 xrefs | 38 个引用地址；该操作未提供引用种类 |
| DLL 函数 `ar_compute` | `0x180001230` 的汇编、伪代码、引用和 p-code |
| 从该地址开始的 DLL 有界值流 | 11 节点、14 边、一次反编译；未报告截断或 unknown |

包装器检查 baseline 大小/SHA-256、后端 Evidence 身份与操作、选定引擎来源，以及查询后目标字节未变。
组合值追踪父 provider 为 `rea-workflow`，组成函数来自 Ghidra。
完整原始 JSON、限制和错误留在 `build/rea-audit-validation/20261020/`，中断及失败尝试也保留。
静态流不证明可利用性、运行时可达性或不存在内存缺陷。

子模块固定上游 `bb154d1067b0fc250452b7d468d0b0523031a16f`（源码版本 6.4.0）。
已检查干净检出及公开接口，未完整执行开发构建；原生验证通过 `--rea-root` 使用独立官方安装包。
未测 IDA/Hopper、其他 bridge actions 或 MCP 客户端注册。未测 CPU 时间、进程族内存峰值，不作性能比较。

可移植回归覆盖危险导入正/负对照、baseline/扫描器变化、包布局、证据保留、CLI 参数边界、
错误目标/操作/provider 信封、组合来源、后端缺失及查询期间目标被修改/删除。
ZIP 计划功能在没有 REA、仓库导入或 Python site packages 时也可运行。
当次完整 Python 运行共 78 项（4 项平台/权限跳过），skill 格式及 MkDocs 严格构建均通过。

## 保护前后泄露验证与性能（2026-10-20）

使用上述 LLVM、Intel/MSVC 环境和 libsodium，对当前 demo 重新完整构建验收。
私有证据：`build/windows-acceptance/20261020T040733401395Z/result.json`。
Debug/Release × OFF/ON 各 39 项 RTTI/异常检查通过，原名/整包门禁、恢复、搬迁、同钥重建和全部
六对象换钥重编译也通过。Release 精确语料命中从 6 次变为 0，元数据无未检查项。

### REA 泄露对照

真实 skill bridge 使用官方 REA 6.4.0 和 Ghidra 12.1.4 检查两组新 Release 包，
每次查询绑定对应扫描报告和产物 SHA-256。这是对早先“仅未保护包”复核的补充，不是模拟响应。

| Ghidra 已定义字符串查询 | 原始版 | 保护版 |
| --- | ---: | ---: |
| EXE：`Invalid mesh topology` | 1 | 0 |
| EXE：`ResonantKernel`，含复合/指针类型 | 6 | 0 |
| DLL：`ResonantKernel` | 2 | 0 |

保护 DLL 的必要公开函数 `ar_compute` 在 `0x180001230` 被找到，并成功恢复八条指令和非空伪代码。
这既证明后端仍可分析，也说明基础信息保护不隐藏普通机器码逻辑。
表内是 Ghidra 已定义字符串记录数，不是扫描器的精确语料出现次数。
Ghidra 零结果不能单独证明字节不存在；独立精确扫描和所有选定原始 RTTI 检查也已通过。

八个成功静态查询、Evidence 信封及核验脚本保留在
`build/rea-leakage-validation/20261020T040733401395Z/`。
首次因 provider 未配置而失败的记录也保留，随后设置已有 `GHIDRA_INSTALL_DIR` 重试成功。
REA 分析期间未执行目标。使用的是独立官方后端，固定子模块的完整开发构建仍未验证，未声称发现新漏洞。

### 原生性能测量

机器：Windows 11 build 26200，Ryzen 9 7900X（12 核/24 线程），平衡电源计划。
构建使用 8 并行、Release `/O2`、相同 CRT 和 `/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO`。
混淆为 `NONE`，因此以下是诊断/位置/RTTI 基础信息保护的成本，不是 Windows xollvm/VM 成本。

`tools/measure_windows.py` 校验验收产物哈希及独立策略参考值。
首轮每项每配置预热 5 次、采样 31 次；单独复测预热 10 次、采样 101 次。
两配置交替顺序，不与 REA 同时运行，不删除慢样本。下表采用复测中位数，
构建时间仍为同一次初始编译/链接观测，不含配置、测试和安装。

| 指标 | OFF | ON | 观测变化 |
| --- | ---: | ---: | ---: |
| 初始编译/链接 (s) | 3.442 | 4.490 | +30.4%，仅一次观测 |
| EXE + engine DLL（字节） | 113664 | 100352 | -11.7% |
| 启动进程中位数 (ms) | 7.342 | 8.291 | +0.950 ms / +12.9% |
| 500,000 次策略循环内部中位数 (ms) | 2.696 | 2.623 | -2.7%，不能称为加速 |
| 输出一次警告的进程中位数 (ms) | 7.178 | 8.493 | +1.315 ms / +18.3% |

首轮 OFF/ON 中位数：启动 7.638/8.232 ms，策略循环 2.686/2.624 ms，警告进程 7.173/9.322 ms。
两次均未观察到明确的策略循环回退，但没有测每次 RTTI 转换或持续诊断吞吐量。
警告时间包含进程加载及 I/O，不是纯加密时间。

**尾部延迟不能忽略。** 复测进程总耗时如下：

| 负载 | OFF p95 / 最大值 (ms) | ON p95 / 最大值 (ms) |
| --- | ---: | ---: |
| 启动 | 8.449 / 10.505 | 110.318 / 122.676 |
| 策略基准进程 | 11.719 / 12.495 | 112.516 / 122.782 |
| 单次警告进程 | 23.442 / 101.629 | 120.372 / 402.091 |

首轮也出现约 120 ms 的保护进程慢样本。延迟原因尚未确定，没有修改杀毒软件或系统设置。
不能据此保证低开销或满足延迟预算；即使进程耗时明显增大，策略循环内部仍约 2.6 ms。

所用 libsodium DLL 为 462848 字节，仅保护 EXE 导入它。
验收脚本将它复制到两组暂存包，得到 576534/563222 字节，但不能据此声称最小部署包变小。
原始包移除未使用 DLL 后，含资源为 113686 字节；保护包含 libsodium 为 563222 字节，均不含共享系统 CRT。

原始样本、离散程度、验收身份和匹配运行脚本快照保存在私有
`build/windows-cost/20261020T040733401395Z/` 及相邻 `20261020T040733401395Z-repeat/`。
未测 CPU 时间、内存峰值、真实 Palace 或 Windows 混淆/VM 成本。
可移植回归共 82 项，4 项平台/权限跳过。
