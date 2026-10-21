# 可选名称混淆

[English](name-styles.md) | 简体中文

名称策略独立于指令混淆和发布剥离。默认仍为 `ANTI_REA_NAME_STYLE=OPAQUE`。
原来的 RTTI 类型名使用稳定不透明标识，不能直接删除，否则会影响运行时类型识别；
普通内部函数符号通常在链接时省略或在发布时剥离。

## 用户选项

| 选项 | 行为 |
| --- | --- |
| `ANTI_REA_NAME_STYLE=OPAQUE` | 保持原有 RTTI 标识及发布符号策略，不新增函数改名 |
| `ANTI_REA_NAME_STYLE=DECOY` | 使用常见功能词替换选定内部函数名和 RTTI 类名 |
| `ANTI_REA_RETAIN_DECOY_EXPORTS=OFF` | 默认，不为保留函数替代名新增导出 |
| `ANTI_REA_RETAIN_DECOY_EXPORTS=ON` | 仅 Windows DECOY 模式，将选定函数替代名保留为 EXE 导出 |

示例替代名为 `read_buffer_<64位十六进制标识>` 和 `CacheEntry_<64位十六进制标识>`。
功能词来自常用代码词表，不表达真实实现。HMAC 后缀用于区分不同类型和函数，避免同名合并；
同钥同原名得到同一替代名，换钥必须完整重编译相关生产者和消费者。这些名称不是加密。
CMake GUI 也可以选择名称模式及保留导出复选框。

```powershell
# 补齐现有 Python、opt、libsodium 和私有密钥参数。
cmake -S . -B build/decoy -DANTI_REA_CODE_PROTECTION=ON `
  -DANTI_REA_NAME_STYLE=DECOY `
  -DCMAKE_CXX_COMPILER=F:/Program_Professional/xollvm-windows-llvm23-Release/bin/clang-cl.exe

# 显式选择在发布 EXE 中保留四个函数的替代名。
cmake -S . -B build/decoy-visible -DANTI_REA_CODE_PROTECTION=ON `
  -DANTI_REA_NAME_STYLE=DECOY -DANTI_REA_RETAIN_DECOY_EXPORTS=ON `
  -DCMAKE_CXX_COMPILER=F:/Program_Professional/xollvm-windows-llvm23-Release/bin/clang-cl.exe
```

使用独立构建目录。两项均要求总保护 ON；strip 仍独立设置。
名称替换支持两种 ABI；保留导出只实现 Windows EXE。

## 范围和发布可见性

`examples/name-policy.json` 显式列出 `policy_dispatch`、`policy_token`、`print_rtti`、
`peer_type` 四个自有函数的 Itanium/MSVC 精确符号。`ANTI_REA_NAME_POLICY` 可以指定其他
经过审查的清单。它不是任意 C++ 工程的自动改名器：公开 API、导入、入口点、按名称查找的
函数及存在未覆盖消费者的函数不能加入。修改清单会触发 demo 对象重编译。

启动器只替换完整 LLVM global/comdat 标识符，更新调用及地址引用，不替换普通字符串和注释。
遇到 DLL 导入/导出、默认可见 ELF 函数、检测到的文本符号引用或冲突时拒绝转换。
函数改名在 xollvm 选择和验证之后执行，并在生成机器码前再次校验 IR。

RTTI 仍只处理自有类型、包含自有类型的复合类型和原先选定的局部类型。
按 ABI 替换名称及数组长度，保留运行时字段、继承关系、虚表和异常引用，无关第三方 RTTI 不变。
这不代表成员链接符号和调试记录全部改名，仍需原有发布隔离策略。

Windows PE 通常不保留内部函数符号。只在 COFF 对象或私有 PDB 中看到函数替代名，
不能证明发布 EXE 会显示这些名字。保留导出 OFF 时，分别记录实际保留替代名的符号通道；
RTTI 替代名则在运行时使用的位置保留。

保留导出 ON 时，四个指定函数以替代名进入 EXE 导出表，engine DLL 原有导出不变。
这会额外暴露函数入口地址，可能方便分析，因此作为默认关闭的可选实验提供。
它不发布 PDB，也不修改调用签名。用于其他 EXE 前需要审查其原有导出策略。

## 恢复与验收

`private/maps/*.json` 的 `rtti`、`symbols` 记录保留原名、可读名称和替代名。
映射、命名密钥、IR 和 PDB 均须内部保存。两个解码器均支持新名称：

```powershell
python tools/anti_rea.py decode --build build/decoy --rtti '完整RTTI替代名'
python tools/anti_rea.py decode --build build/decoy --symbol '完整函数替代名'
python <skill>/scripts/decode.py --build /private/build --symbol '完整函数替代名'

# acceptance 为现有 LLVM、Intel 环境、libsodium 等参数数组。
python tools/validate_windows.py @acceptance --name-style DECOY `
  --retain-decoy-exports ON --out build/name-check-new-run
```

独立 RTTI/符号查询不需要加密依赖，`--symbol` 必须完整匹配。
原生验收检查 Debug/Release、39 项跨 TU/DLL RTTI/异常边界、数值输出、安装搬迁、
正式链接参数、私有 PDB、六个编译对象、COFF 名称、PE 导出、映射、同钥重建及换钥。
增加 `--obfuscation MIXED_VM` 可检查与 VM 的组合。

2026-10-21 原生 Windows 使用 LLVM 23.1.2、Intel oneAPI 环境和 8 个并行编译任务验证。
DECOY 不增加导出的配置已通过；保留四个 EXE 替代导出的配置也通过完整 NONE、MIXED_VM 验收，
包括 Debug、Release、正式链接参数、映射恢复及六对象换钥重编译。
独立 ZIP 解码器在没有 site-packages 时恢复了 4 个选定函数和 19 个自有 RTTI 名称；
额外发布扫描中，指定原函数名及 `ResonantKernel` 命中数为 0。
原始证据内部保存，不进入公开文档及下载包。

“原名消失、替代名生效、行为一致”可以直接验收；“让大模型猜错功能”是尚未验证的独立假设。
评估后者需要同条件 OPAQUE/DECOY 对照、向分析者隐藏源码和映射、记录模型版本和提示词，
依据源码确定的行为评分，并记录不确定性和分析时间。出现看似合理的功能词不等于证明模型会误判；
汇编、调用关系、常量和数据流仍可被分析。
