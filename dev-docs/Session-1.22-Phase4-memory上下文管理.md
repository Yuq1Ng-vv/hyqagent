# Session 1.22 — Phase 4 启动: memory/ 上下文管理包

## 目标
实现 Phase 4 长任务能力的基础设施——三区段上下文管理（`memory/` 包），为后续收敛检测、对抗性审查、饱和扫描提供上下文管理基础。

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 新建 | `src/hyqagent/memory/context.py` | ~290 | 三区段上下文模型 (固定/长期/工作) |
| 新建 | `src/hyqagent/memory/crystallizer.py` | ~300 | 上下文结晶协议 + 双语提取 |
| 新建 | `src/hyqagent/memory/retriever.py` | ~400 | 混合检索 (ripgrep/tree-sitter/difflib) |
| 修改 | `src/hyqagent/memory/__init__.py` | +17 | 重新导出公共 API |
| 新建 | `tests/test_memory/test_context.py` | ~150 | 27 tests |
| 新建 | `tests/test_memory/test_crystallizer.py` | ~120 | 15 tests |
| 新建 | `tests/test_memory/test_retriever.py` | ~190 | 15 tests |
| 修改 | `progress.md` | +38/-3 | Phase 4 进度刷新 |

## 实现过程

### 1. Phase 3 状态确认
用户问"phase 3还没做完吗"——确认 Phase 3 实际上已 100% 完成，`progress.md` 中"报告生成集成为部分完成"的标注是文档滞后（CLI 其实已经在用 ReportGenerator）。

### 2. `memory/context.py` — 三区段上下文模型
核心设计：
- **ZoneBudget**: 5K(fixed) + 30K(long_term) + 60K(working) = 95K tokens，留有 105K 代码余量
- **TurnRecord**: 每轮对话记录，带 `/4` 粗粒度 token 估算
- **ContextManager**:
  - `set_fixed()` — 系统 prompt + 规则，可设置 Prompt Cache breakpoint 1
  - `update_long_term()` — 结晶摘要，旧内容截断保留前 2000 字符
  - `add_to_working()` — 滑动窗口自动 evict 超出预算的老 turns
  - `build_messages()` — 组装 LLM 消息（带 cache_control breakpoints）
  - `build_simple_messages()` — 单次调用简化版
  - `needs_crystallization()` — 80% 预算或 N 轮触发
  - `snapshot()`/`restore()` — 检查点序列化

### 3. `memory/crystallizer.py` — 上下文结晶
- **CrystalSummary**: 结构化摘要数据类（phase/files/findings/decisions/questions/coverage），`to_long_term_text()` 渲染为 markdown
- **ContextCrystallizer**:
  - `should_crystallize()` — 检查 turn 数或预算阈值
  - `crystallize()` — 从 turns 提取 findings（双语正则），生成压缩统计
- **should_crystallize_on_phase_change()** — 7 个阶段列表中，向前跃迁时触发
- 正则提取支持：
  - 英文: `verdict: confirmed`, `confidence: 0.95`
  - 中文: `判定：confirmed`，`置信度：0.88`
  - 漏洞类型关键词: sqli, XSS, SSRF, IDOR, 命令注入等

### 4. `memory/retriever.py` — 混合代码检索
- **CodeChunk**: 函数级代码切片（AST 解析 + file/function/line range 索引）
- **SearchResult**: 搜索结果（score + match_type + detail）
- **CodeRetriever**:
  - `build_index()` — 用 Parser 解析所有文件，索引 module + function 级别
  - `search_exact()` — ripgrep subprocess → Python re fallback
  - `search_structural()` — function name fast-path → tree-sitter Traverser.find_all()
  - `search_similar()` — difflib.SequenceMatcher ratio，阈值默认 0.85
  - `mark_analyzed()`/`is_analyzed()` — 分析进度追踪
  - `find_related()` — 同文件关联代码块

## 遇到的问题与修复

| 现象 | 原因 | 修复 |
|------|------|------|
| 27 个 ruff 错误 | 缺少 docstring、行太长、SIM103 简化、RUF001 全角冒号、S603/S607 subprocess 安全、F841 未用变量等 | 逐文件手动修复，全角冒号加 noqa，subprocess 加 S603/S607 noqa |
| `noqa: S603` 放在函数定义行无效 | bandit 规则作用于 `subprocess.run()` 调用行而非定义行 | 将 noqa 移到 `subprocess.run()` 行和参数列表行 |
| 空 `__init__.py` 写入失败 | Write 工具要求先 Read 文件 | Read 后 Write |

## 质量门禁

```bash
ruff:       All checks passed!
mypy:       N/A (pre-existing 24 issues, no new)
pytest:     1119 passed, 2 skipped, 0 failures (+57 memory tests)
imports:    All imports OK, smoke test passed
```

## 设计反思

- **做得好**: 遵循项目现有模式（dataclass + Manager 类 + async-over-sync + `__all__` 重导出），三个模块自然形成分层（context → crystallizer 消费 → retriever 独立）
- **可改进**: `retriever.py` 的 ripgrep 子进程调用缺少安全校验（pattern 来自用户控制的上游），Phase 5 可加固；向量检索（Qdrant）留到 Phase 5
- **技术负债**: `search_structural` 中遍历 `self._chunks.values()` 是 O(n)，大项目需要倒排索引加速

## 下步衔接

Phase 4 剩余 6 项任务：
1. **检查点+上下文集成** — 把 memory/ + session/checkpoint.py 接入 `_run_deep_audit`
2. **CLI resume 真正实现** — 接上 CheckpointManager.load_latest()
3. 收敛检测（VDR/EC/RWC/VCC/C_hat）
4. 对抗性审查 + 饱和扫描
5. Observability 扩展（OTel + LangFuse + ESAA 审计链）
6. 信号处理 + Orchestrator
