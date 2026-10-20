# 参考项目评估与能力改进

[English](reference-improvements.md) | 简体中文

2026-10-20 对照 [chldbwnstm/ANTI-REA](https://github.com/chldbwnstm/ANTI-REA)，
固定参考提交 `84c4b87a4da583acd30d060bbf01f73ce1e30739`。
参考仓库单独克隆，未替换本项目或引入新的构建依赖；本次改进独立实现，未复制其保护引擎。

## 参考价值与选择

| 参考实现 | 对本项目的价值 | 本次处理 |
| --- | --- | --- |
| `antirea/scope.py` 的调用者、被调用者及共享全局数据审查 | 单独虚拟化核心函数仍会留下包装常量和共享表 | skill 增加周边审查；扫描器增加显式数值语料。尚未实现自动 IR 保护范围推导 |
| `antirea/defense_validate.py` 的工程预算与轮换采样 | 功能正确和性能可接受应分别判定 | Windows 工具及独立测量 skill 增加预算、相对速度及失败退出码 |
| `antirea/judge.py` 的边界、相关输入及独立私有测试 | 区分恢复公式与仅拟合已知样本 | 保留现有边界/holdout 流程；不将参考仓库的结果算作本项目测试 |
| `antirea/hardening.py` 的常量池、环境检测、诱饵和商用配置 | 常量池可减少直接字节特征 | 后续独立实现了五个常量的运行时掩码；环境检测、诱饵、商用配置未移植，未引入静默 key poisoning |

来源分别为固定提交中的
[范围审查](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/scope.py)、
[预算验证](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/defense_validate.py)、
[行为判定](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/judge.py)和
[hardening 模块](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/hardening.py)。
本次审阅未运行参考仓库的 VM、商用工具或外部攻击实验，未复现其 README 的“25%”指标，
不能用它比较两个项目的通用防御能力。

## 数值常量检测

原扫描器着重字符串和元数据。新增 `--constant` 按用户声明的表示查找数值字节，
无需 REA 或反汇编器，可随检测 skill ZIP 独立运行：

```powershell
python skills/cpp-leakage-audit/scripts/audit.py `
  --binary original/app.exe --constant u32le:0x5a827999 `
  --constant f64be:0.125 --require-metadata --out build/private/original
```

支持 `u32le/u32be/u64le/u64be/f32le/f32be/f64le/f64be`，拒绝越界整数及非有限浮点数。
输出类别为 `specified-constant`，记录精确文件偏移，`--fail-on-deny` 可作为发布门槛。
所有数值语料与原有文字语料一样参与 baseline 一致性检查。
扫描器版本已变更，需重新扫描保留的原始产物形成新 baseline，不修改旧报告。

字节命中不证明运行用途、数据类型或所属算法。折叠、拆分和加密后的常量可能不再匹配；
公共或很短的常量可能产生无关命中。skill 要求结合调用者、共享数据和引用审查，
也不根据诱饵函数名、看似密码表的数组就认定真实算法。

## 性能预算

原生 Windows 增加 `--max-bench-slowdown`、`--max-startup-slowdown` 和 `--max-package-ratio`。
独立保护 skill 的测量清单增加可选 `comparisons`：

```json
{"reference": "baseline", "target": "protected", "max_slowdown": 1.25, "max_size_ratio": 2}
```

这些值仅是用法示例。预算在执行前验证并记录，超限返回 1；失败工作负载或缺少有效参考值不能通过。
独立工具还轮换采样顺序、保留每次耗时和 p95、检查预热输出，并在测量后核对声明产物的大小和 SHA-256。
相对速度为 `100 * baseline时间 / protected时间`，与“增加多少耗时”分开报告。
命令格式见[Windows 指南](windows.zh-CN.md)及[测量方法](measurement.zh-CN.md)。

## Windows 实测

复用已验收的 OFF/NONE 与 ON/MIXED_VM 发布包，未重编译、修改目标或执行真实 Palace。
保护 EXE SHA-256 为 `28e69edcd5fe3e231a9479fa56f78a18cc12417ec21d2a0b7fc51f480ad1611b`。

- 原始及保护 EXE 均命中 `u32le:0x5a827999`，文件偏移分别为 28419、33469；逐项读取原始字节复核。
  负对照 `u64le:0x0123456789abcdef` 未命中，结构化元数据没有未检查项。
  保护版的 `--fail-on-deny` 返回 1，正确反映仍有选定常量可见；这不是新增泄露或 RTTI 保护回归。
- 最终原生测量每组预热 3 次、采样 11 次，策略循环中位数为 2.586 / 75.946 ms，
  耗时比率为 29.367，相对速度为 3.405%。预声明 2 倍耗时预算时拒绝；
  另一次以 50 倍预算作宽松正对照时通过（2.578 / 74.792 ms，比率 29.016）。
  50 倍不是建议的生产预算。功能及独立参考值检查均通过。
- 完整暂存包为 576534 / 840726 字节，比率约 1.458，两组均包含 libsodium；2 倍整包预算通过。
  单独的 EXE+engine DLL 比率约 3.324，不能与整包体积比混用。
- 独立 ZIP 工具的真实 Windows `selftest` 测量命中独立预期输出；刻意设置的 0.5 倍体积预算失败并返回 1。
  所有选定 EXE/DLL 测试前后哈希不变。

首次整目录 baseline 比较因资源别名改变、文件清单不同而被拒绝，失败证据保留。
之后常量专项比较明确选择三份同名 EXE/DLL，未把它称为整包比较；体积仍测完整包。
最终从生成的两个独立 skill ZIP 中解压运行工具，通用测量使用 `-I -S` 隔离模式。
92 项回归运行完成，4 项平台/权限检查跳过；两个 skill 格式及 MkDocs 严格构建通过。
最终原生证据为私有 `build/reference-improvements/20261020-r003/results/verification.json`，
首次尝试及后续脚本、响应、快照、原始样本也保留，不随文档或 skill ZIP 发布。
本次没有增加盲测攻击实验，也没有证明常量隐藏或通用去虚拟化能力。

## 后续保护实现

参考 `hardening.py` 的常量池思路，独立实现了五个策略常量的编译期掩码和运行时还原。
新增 `ANTI_REA_CONSTANT_PROTECTION` 开关，默认 ON；只有总保护开关 ON 时生效。
可在同一信息保护与混淆等级下设为 OFF，单独对照常量保护的收益和成本。
数值热点未加入此机制。

`examples/policy-constants.json` 声明目标，生成器通过域分离的 HMAC 派生每项掩码，
生成 `policy_constants.hpp`，内部映射保留在 `private/constants.json`。
编译后的两份数据通过 volatile 读取再 XOR，避免 `/O2` 折叠回原常量。
主密钥不用于运行时解码，不需要进入 EXE/DLL。

这属于可逆的数值混淆，不具备公钥密封诊断那样的保密边界。
二进制自带还原数据与逻辑，相邻 XOR 数据甚至可由已知语料的配对扫描恢复。
因此验收必须分别报告“直接明文字节是否消失”“运行行为与性能是否达标”和“分析者能否恢复”。
前文旧样本中常量可见的结论仍然成立；新机制需要新构建证据，不能修改旧报告。

### 新构建验收结果

使用同一套 Clang/LLVM 23.1.2、Intel 环境、8 并行任务与
`/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO`，重新完成 NONE 和 MIXED_VM
各自的 Debug/Release、总保护 OFF/ON 四组验收。
原始 EXE 中五个指定常量均命中；新保护包 EXE、engine DLL 中均无其直接明文字节。
39 项 RTTI/异常边界、每个策略函数 1088 组独立公式输入、诊断恢复、搬迁资源、
六个编译对象覆盖、同密钥重建与换钥后的完整重编译均通过。
MIXED_VM 的 VM 和 flattening 报告确实执行，未将跳过当作成功。

随后只切换常量保护开关，保持信息保护、混淆等级和密钥一致，建立 Release 控制组。
每组预热 3 次、轮换采样 11 次，预先声明额外耗时上限 1.5 倍、整包体积上限 1.1 倍。

| 混淆等级 | 常量 OFF 循环中位数 | 常量 ON 循环中位数 | 额外耗时 | 整包体积变化 | 预算 |
| --- | ---: | ---: | ---: | ---: | --- |
| NONE | 2.7126 ms | 2.7765 ms | +2.36% | 相同 | 通过 |
| MIXED_VM | 75.9654 ms | 117.6920 ms | +54.93% | +1024 字节（约 0.12%） | 耗时未通过 |

这些是本机 demo 的局部观测，不是其他程序的固定开销。
另将 VM+常量保护与原始总保护 OFF 对照，循环耗时为 2.554 / 116.874 ms，
约 45.76 倍，超过预先声明的 2 倍预算，正式测量工具正确返回 1。
不能用“常量保护仅增加 2.36%”描述 VM 组合。

**恢复检查未达成防还原目标。** 独立脚本仅读取最终 EXE 和五个已知常量，
没有读取密钥、生成头文件、映射或 PDB，便通过相邻 DWORD 的 XOR 找回全部五项；
Capstone 5.0.7 还确认代码中存在对应数据地址引用。
例如最终 MIXED_VM EXE 偏移 331744 处的两个 DWORD 可恢复 `0x5a827999`。
这属于已知语料的恢复验证，不是盲测恢复完整算法，也不是完整 VM 去虚拟化。
当前聊天 REA 的 Ghidra 后端缺少 Windows native manifest、IDA 未注册，
本轮没有新的 REA 反编译结果，未将后端不可用计为保护成功。

最终 NONE / MIXED_VM 旋转密钥后 EXE 的 SHA-256 分别为
`11307cedb2c3f4ad792d9327bb7ae353047c38cfa211788eec06d82a6c434feb` /
`7abfbbd6362c0ddb65f15a874565d1d6c4f15622a3ddf12e4957cc425818a674`。
证据位于私有 `build/constant-protection/20261020-r002/` 下的
`plain/result.json`、`mixed/result.json`、`plain-cost/result.json`、
`mixed-cost/result.json`、`mixed-total-cost/result.json` 和两份 `*-recovery.json`。
首轮 `r001` 的访问函数会干扰 VM 成本比较，已保留；最终版本用直接表达式消除该干扰。
全部测试前后产物哈希一致；94 项 Python 回归在 Windows/Linux 均完成，分别跳过 4/2 项平台检查。

本次采纳的能力是低成本减少指定直接字节特征，并保留可复现的关闭开关。
它没有证明抗 REA 或防常量还原；当前 VM 热循环组合的性能验收也不通过。
