# Windows x64：clang-cl、JOM 与发布审计

[English](windows.md) | 简体中文

## 状态和前置条件

Linux 成功不能证明 MSVC ABI 正确。实际 Windows demo 的工具链、CRT 和完成范围见[原生验证记录](windows-validation.zh-CN.md)。

- x64 Visual Studio 开发环境、Windows SDK 和 C++ 运行库。
- CMake 3.24+、JOM、Python 3.10+、`requirements.txt`。
- clang-cl 和匹配 opt；xollvm 使用 LLVM 22/23 静态扩展版。
- 编译器旁或 PATH 中 `llvm-undname.exe`，不可用时自动用原生 DbgHelp。
- libsodium 头、MSVC 导入库及运行 DLL，如 vcpkg `libsodium:x64-windows`。

普通 `cl.exe` 无法运行此 IR 保护链；不承诺 Windows 动态 pass 插件支持。

## 构建与测试

开发环境中运行完整验收：

```powershell
python tools/validate_windows.py `
  --llvm-bin F:/Program_Professional/xollvm-windows-llvm23-Release/bin `
  --environment F:/Intel/oneAPI/setvars.bat `
  --sodium-prefix C:/deps/installed/x64-windows `
  --sodium-runtime C:/deps/installed/x64-windows/bin/libsodium.dll
```

已初始化开发 shell 可省 `--environment`。prefix 需含 `include/sodium.h` 和 `lib` 下导入库，其他布局用 `--sodium-library`；传入真实依赖 DLL 并复制到每个新发布包，不能靠 PATH 掩盖缺失。默认 JOM，也支持 `--generator Ninja`，默认 8 并行任务。操作者提供依赖，脚本不下载安装。

每次使用独立 `build/windows-acceptance/<UTC-run-id>/`，保留命令、日志、新密钥、私有 IR/映射、报告、发布包和 `result.json`。失败非零退出并保留证据，整目录不可公开。

Debug/Release × OFF/ON 全部使用 `/DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO`。每 EXE 验证 39 项 RTTI/异常，包括原始 baseline、指定名称消失、无关类型保留、映射恢复、六个编译对象、同钥干净重建和增量完整换钥；检查 CodeView、内部 PDB、公共导出、私钥缺失、整包及搬迁加载。

单次构建可在 x64 开发 PowerShell 中运行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

cmake --preset windows-jom `
  -DCMAKE_CXX_COMPILER=C:/tools/xollvm/bin/clang-cl.exe `
  -DANTI_REA_OPT=C:/tools/xollvm/bin/opt.exe `
  -DCMAKE_PREFIX_PATH=C:/deps/installed/x64-windows
cmake --build --preset windows-jom
ctest --test-dir build/windows-jom --output-on-failure
cmake --install build/windows-jom
```

测试时将 libsodium DLL 目录加入 PATH，或按部署策略放在程序旁；不分发整个依赖安装/SDK。mixed VM 增加 `-DANTI_REA_OBFUSCATION=MIXED_VM`，不同配置用独立目录。Linux 工具包仅用于 WSL，不能直接给原生 JOM 用。

## MSVC RTTI 契约

Itanium `_ZTS` 不是 MSVC RTTI。转换器识别 Clang x64 `TypeDescriptor`，修改名称缓冲及数组大小，保留运行字段和引用。不支持的布局明确失败。

所有生产者/消费者统一 HMAC 域、密钥和选择策略。`rtti-test` 覆盖 EXE/DLL 不同描述符、双向转换、单/多/虚继承、失败指针/引用转换、`bad_typeid`、跨 TU 相等、哈希、排序和容器；异常包括精确/基类/无关捕获、重抛、`exception_ptr`、指针转换和 const 拒绝。不是任意预编译插件生态兼容性证明。

launcher 支持 `--`、`-TP`、`/Fo...`、嵌套响应文件及引号路径，保留运行库选项。PCH、modules、LTO、sanitizer 等需另做验收。

## PE/PDB 发布规则

ELF `strip --strip-all` 不适用 PE。保护对象移除私有源码元数据，链接使用 `/PDBALTPATH:<target-pdb-basename>`，仅记录 PDB 文件名。显式 basename 避免 JOM 破坏 `%_PDB%`。PDB 和 IR 不安装；保护 PDB 仍含链接符号，但缺少被移除的源码调试信息。

```powershell
python tools/anti_rea.py audit `
  --binary out/windows-jom/bin/anti-rea-demo.exe `
  --binary out/windows-jom/bin/engine.dll `
  --deny "Invalid mesh topology" --deny "ResonantKernel" `
  --require-metadata --fail-on-deny --out build/windows-release-audit
```

检查导入导出、RTTI 候选、文件名和 CodeView。系统 DLL 导入不是内部算法泄露。扫描器不解析 PDB 内容，最终打包审计后再签名。

工作流定义包含托管 Windows 上的便携测试及手动触发的自托管原生验收；仓库可能单独禁用工作流，需核对实际运行状态。托管 Python 通过不等于原生 ABI 验收。私有原生证据不上传为公开 artifact。
