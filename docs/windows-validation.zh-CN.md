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
