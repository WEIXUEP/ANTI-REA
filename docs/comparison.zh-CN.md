# 实测对比

[English](comparison.md) | 简体中文

数据由 `tools/anti_rea.py compare` 生成，不含模拟测量。

## 环境

- Linux x86_64；clang 23.1.2，LLVM 提交 `ba019b7aafce09a013cf7e9139fa0c229f09b188`（<https://github.com/llvm/llvm-project>）。
- 八个构建任务，每种负载九个样本。
- 所有完成项使用相同编译器、RelWithDebInfo 和 O2。
- 构建时间为一次全新编译/链接观测，不含配置、测试和安装。
- 体积包含主程序和示例共享库，不含系统依赖。

## 结果

| 配置 | 状态 | 构建 (s) | 字节数 | Bench 中位数 (ms) | 启动中位数 (ms) | 禁止语料命中 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| baseline | Passed | 1.016 | 494720 | 2.633 | 1.072 | 71 |
| stripped | Passed | 0.966 | 54288 | 2.630 | 1.069 | 23 |
| protected | Passed | 1.167 | 62536 | 2.613 | 1.161 | 0 |
| obfuscated-light | Passed | 1.217 | 66672 | 4.390 | 1.139 | 0 |
| obfuscated-medium | Passed | 1.267 | 66672 | 5.107 | 1.172 | 0 |
| obfuscated-heavy | Passed | 1.217 | 70768 | 44.339 | 1.145 | 0 |
| mixed-vm | Passed | 2.620 | 300152 | 78.344 | 1.161 | 0 |

## 证据与边界

各配置测试均通过，审计分类计数如下（保留原始字段名）：

- **baseline**：`{'denied-text': 71, 'rtti': 38, 'url': 4, 'path': 44, 'filename': 115, 'import-symbol': 102, 'export-symbol': 37, 'runtime-path': 2, 'debug-metadata': 18, 'static-symbol': 220}`
- **stripped**：`{'denied-text': 23, 'rtti': 18, 'url': 2, 'import-symbol': 102, 'export-symbol': 37, 'runtime-path': 2, 'path': 3, 'filename': 1}`
- **protected**：`{'rtti': 13, 'url': 2, 'import-symbol': 113, 'export-symbol': 5, 'runtime-path': 2, 'path': 2}`
- **obfuscated-light**：`{'rtti': 13, 'url': 2, 'import-symbol': 113, 'export-symbol': 5, 'runtime-path': 2, 'path': 2}`
- **obfuscated-medium**：`{'rtti': 13, 'url': 2, 'import-symbol': 113, 'export-symbol': 5, 'runtime-path': 2, 'path': 2}`
- **obfuscated-heavy**：`{'rtti': 13, 'url': 2, 'import-symbol': 113, 'export-symbol': 5, 'runtime-path': 2, 'path': 2}`
- **mixed-vm**：`{'rtti': 13, 'url': 2, 'import-symbol': 114, 'export-symbol': 5, 'runtime-path': 2, 'path': 2}`

仅 `denied_matches` 是此示例的敏感文本门禁，其他发现仍须审阅。
私有构建文件可以包含原始标识符，安装发布包是另一组独立产物。
文件更小、字符串更少不能量化对熟练逆向人员的抵抗能力。
随机 sealed 密文会使全新配置的二进制哈希不同。
此 Linux 矩阵不声称验证了 Windows 执行，也不将缺少工具链的 xollvm 配置列为已测。
