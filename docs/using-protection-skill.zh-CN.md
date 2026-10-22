# 代码保护 Skill

[English](using-protection-skill.md) | 简体中文

`cpp-code-protection` 指导限定范围的 C++ 保护实现、密钥管理、离线恢复和工作负载测量。它独立于只读[检测 skill](audit-skill.zh-CN.md)，不附带扫描器。

## 安装与能力

[下载 cpp-code-protection](downloads/cpp-code-protection.zip)，解压到代理 skill 目录，或复制 `skills/cpp-code-protection`。Python 3.10+ 可运行独立工具；PyNaCl 支持兼容的密钥生成和密封事件恢复，不依赖示例仓库。代理入口为 `SKILL.md`，skill 及其参考文档保持英文。

| 能力 | 入口 |
| --- | --- |
| 检查依赖及 LLVM/xollvm | `scripts/doctor.py` |
| 生成私有恢复材料 | `scripts/generate_keys.py` |
| 恢复支持格式的诊断、位置、RTTI | `scripts/decode.py` |
| 测量可信目标工作负载 | `scripts/measure.py` |
| C++ 保护和选择性混淆 | 代理依据参考文档修改目标 |
| 指定策略常量掩码与取舍验证 | [常量操作流程（英文）](protection-skill/references/runtime-constants.md)；demo 生成需源码仓库 |
| 解码 GUI 设计 | 基于共享后端的设计指导，未附带 GUI |

```bash
python <skill-directory>/scripts/doctor.py
python <skill-directory>/scripts/generate_keys.py --out /private/r17/keys.json
python <skill-directory>/scripts/decode.py --build /private/r17/build \
  --keys /private/r17/keys.json --report warning.log
python <skill-directory>/scripts/decode.py --build /private/r17/build --list-maps
python <skill-directory>/scripts/measure.py --config workloads.json \
  --samples 9 --warmups 2 --out /private/reports/workloads
```

生成器和解码器支持文档中的示例 schema，不支持任意产品格式。原名映射不是加密载荷，查表成功不等于解密。运行时只携带诊断加密公钥，私钥、命名密钥、映射、IR 和调试文件不能进入部署包。

## 给代理的请求示例

```text
使用 $cpp-code-protection 规划此 C++ 引擎的保护，暂不修改。
保留公共 ABI、异常和 RTTI 行为，明确中央诊断接口、目标及消费者覆盖、密钥存储和验收测试。
```

```text
使用 $cpp-code-protection 实施已授权的一方代码保护。
启用发布剥离及诊断、位置、RTTI 基础保护。
额外混淆按函数价值和实测预算选择，保留数值热点。
重建、测试恢复，并用原始敏感语料重新检查全新安装包。
```

仅设计任务不包含生成密钥或构建。现有审计工具也可提供 baseline 和最终证据，检测 skill 不是前置依赖。

## 常量保护与 Windows 验收

Skill 新增[已核对的常量操作流程（英文）](protection-skill/references/runtime-constants.md)，
包含 `ANTI_REA_CONSTANT_PROTECTION` 开关、私有映射、LLVM 23/Intel oneAPI 的 Windows
验收命令、同级掩码 OFF/ON 对照及独立测量配置。demo 生成和原生验收需已有源码仓库，
下载的 Skill 则可独立测量现有可信程序。`decode.py` 不读取数值常量映射。

```text
使用 $cpp-code-protection 验证这个自有 Windows demo，先保留原始 baseline。
只掩码选定策略常量，验证 Debug/Release 行为、RTTI/EH、跨 DLL 类型识别、
正式链接参数、搬迁及换钥后的完整重编译。
在同一混淆级别、同一密钥和参数下比较掩码 OFF/ON，
分别报告原始字节隐藏、可恢复性、事先约定的运行和体积预算。
```

已测 demo 的 5 项原始字节签名消失，但全部仍可从相邻 XOR 分片恢复。
NONE 下掩码增加 2.36% 循环时间；MIXED_VM 下相对同级对照增加 54.93%，
未通过 1.5 倍时间门槛。这些是 demo 实测，不能作为其他项目的性能承诺。
参见[新构建验收记录](reference-improvements.zh-CN.md)。

## 规范说明

[可选名称模式](name-styles.zh-CN.md) 新增常见功能词函数/类型替代名及私有映射，
保留原有不透明模式作为默认。Windows 可显式保留指定 EXE 导出替代名，
但会额外暴露地址，因此默认关闭。Skill 包含[已验证的接入与恢复规则（英文）](protection-skill/references/name-styles.md)。
目前不宣称已证明大模型会误判。

[运行时资源方案（英文）](protection-skill/references/runtime-resources.md) 提供可选的
AES-GCM 打包、内存消费和跨进程派生结果缓存设计；内嵌密钥仍可被提取。
该流程要求原程序 baseline 及目标实现的独立验收。Skill 尚不包含资源打包器、
资源密钥生成器或缓存运行库，文档及 ZIP 检查通过不能证明资源加密与缓存已可运行。

- [Skill 说明（英文）](protection-skill/index.md)
- [独立操作（英文）](protection-skill/references/operations.md)
- [接入契约（英文）](protection-skill/references/integration.md)
- [修复与函数选择（英文）](protection-skill/references/remediation.md)
- [运行时常量、对照与原生验收（英文）](protection-skill/references/runtime-constants.md)
- [加密运行时资源与缓存设计（英文）](protection-skill/references/runtime-resources.md)
- [密钥生命周期（英文）](protection-skill/references/key-management.md)
- [离线恢复和 GUI（英文）](protection-skill/references/recovery-tools.md)
- [验证（英文）](protection-skill/references/validation.md)
- [Windows 验收（英文）](protection-skill/references/windows.md)

下载包采用显式白名单并在仓库外测试。加密、不透明命名、剥离、混淆针对不同通道，不能保证原生代码无法逆向。
