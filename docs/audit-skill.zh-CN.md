# 泄露检测 Skill

[English](audit-skill.md) | 简体中文

`cpp-leakage-audit` 是独立的只读源码和原生发布包审计 skill，查找诊断、条件、路径、名称、RTTI 和私有产物，依据证据提出建议。可选 REA 将范围扩展到原生安全调查；漏洞候选与已确认信息泄露分别报告。

加密、构建修改、密钥和恢复工具由独立的[代码保护 skill](using-protection-skill.zh-CN.md)负责，二者互不依赖。

## 安装与运行

[下载 cpp-leakage-audit](downloads/cpp-leakage-audit.zip)，解压到代理的 skill 目录，或复制仓库 `skills/cpp-leakage-audit`。不会全局安装任何内容。`SKILL.md` 为代理入口，skill 及其参考文档保持英文。

基本扫描需 Python 3.10+；可选 pyelftools/pefile 提供结构化元数据解析，在选定环境安装 `scripts/requirements.txt`。包内不含密钥生成或目标重写功能。

```bash
python <skill-directory>/scripts/audit.py --source /authorized/source \
  --binary /original/app --binary /original/engine.so \
  --deny-file sensitive-corpus.json --require-metadata \
  --out /private/reports/original
python <skill-directory>/scripts/audit.py --package /staged/release \
  --fail-on-private --require-metadata --out /private/reports/package
```

路径始终检测，指定函数名/变量名默认为空。`--all-strings` 输出私有的全局可读字符串清单。baseline 和报告含敏感证据，禁止安装到发布包。

数值语料可重复指定，例如 `--constant u32le:0x5a827999 --constant f64be:0.125`。
支持无符号 32/64 位整数及 IEEE-754 32/64 位浮点数的大小端编码，记录精确文件偏移，
并纳入 baseline 语料一致性检查及 `--fail-on-deny` 门槛。命中证明字节存在，不证明计算用途；
还需检查调用者、共享表和相关引用，不能只查被虚拟化的函数体。
参见[参考项目改进及 Windows 实测](reference-improvements.zh-CN.md)。

## 常量掩码反证检查

下载 ZIP 新增已独立验证的标准库工具：

```bash
python <skill-directory>/scripts/probe_constant_pairs.py --binary /protected/app.exe --constant u32le:0x5a827999 --constant u32le:0xa341316c
```

它逐字节检查相邻小端 DWORD 的 XOR 配对，记录哈希、偏移、覆盖范围，并复核输入未变。
退出码 1 表示发现候选或扫描未完整；2 表示输入或完整性错误；0 仅表示这种特定表示没有匹配。
不需要 REA、密钥、映射、PDB，也不执行目标；stdout 报告需私下保存。

先对原程序建立 baseline 并确认原始常量可命中，再对每个保护 EXE/DLL 运行探测。
候选需另用 REA 或指令检查确认相关代码引用，不能直接当成算法恢复。
参见[完整流程及限制（英文）](skill/references/numeric-recovery.md)。
纳入 Skill 前，工具已在保留的最终 NONE、MIXED_VM Windows EXE 上实测：
两者均发现覆盖全部 5 项已知值的 5 个候选，扫描完整、哈希未变；另验证 ZIP 解压后的独立运行。

## 给代理的请求示例

```text
使用 $cpp-leakage-audit 检查源码、原始可执行文件、库和完整发布目录。
任何修改前保存私有 baseline。按偏移或源码行报告诊断、路径、RTTI、符号泄露，
列出有意公开的名称和无法执行的检查。不要修改目标。
```

审计不隐含重编译、strip、生成密钥或安装工具链授权。用户提供修复后的产物时，可用同一语料、顺序和清单比较结果。

## 已验证的 Windows 泄露检查

[原生验证记录](windows-validation.zh-CN.md)包含针对原始及保护 demo 包的真实 REA/Ghidra 查询。
指定诊断/RTTI 查询有已知泄露正对照，保护后的公开函数仍可反编译。
精确字节门禁独立于 Ghidra 的已定义字符串清单；同页也记录保护开销及实测尾部延迟，
不据此声称完成漏洞评估或能抵抗所有分析。

## 虚拟化函数恢复

skill 也可调查指定函数在虚拟化后是否能恢复等价逻辑。先保存原程序 baseline，
并将保护产物绑定到其自身的哈希和报告；缺少原程序时，注明无法验证保护前后改善。
按需进行静态检查、授权范围内的 REA/Frida 观测、处理器分析及独立编译比对。
报告区分静态可见、运行观测、部分恢复和已验证恢复，不将分派器伪代码当成算法恢复。

```text
使用 $cpp-leakage-audit 分析这个 Windows demo 的指定虚拟化函数。
可以在隔离进程中执行和插桩自有 demo，保留原文件。
先建立 baseline；如能恢复，生成私有等价 C++ 并独立编译，使用边界输入和
未参与推导的测试输入与原函数比较。报告未覆盖路径、人工辅助及不确定项。
```

[Windows 验证记录](windows-validation.zh-CN.md)包含一个 VM-light 样本的辅助恢复结果。
ZIP 包含通用调查指导，不包含该样本的私有 trace、地址或专用解码器，也不提供一键去虚拟化。

## 规范说明

- [Skill 说明（英文）](skill/index.md)
- [操作和退出码（英文）](skill/references/operations.md)
- [结果解释（英文）](skill/references/interpretation.md)
- [验证要求（英文）](skill/references/validation.md)
- [Windows PE 审计（英文）](skill/references/windows.md)
- [REA 子模块、CLI/MCP 和漏洞调查（英文）](skill/references/rea.md)
- [虚拟化函数恢复流程（英文）](skill/references/vm-recovery.md)
- [数值 baseline 与恢复反证（英文）](skill/references/numeric-recovery.md)

网站和 ZIP 使用相同的白名单源文件。源码启发式检测不是 C++ 解析器；字节匹配不能证明运行路径，零匹配也不意味着无法逆向。
