# Session 1.41 — OpenAI Provider API 连接问题诊断与修复

## 目标
用户反馈切换到 OpenAI 格式 API 后 LLM 调用一直不通，需要诊断根因并修复。

## 产出清单
| 文件 | 变更 |
|------|------|
| `src/hyqagent/api/config.py` | `openai_key` 属性增加 `deepseek_key` 兜底逻辑 |
| `src/hyqagent/models/providers/openai_provider.py` | 修复 tenacity retry 不再重试 4xx 非可恢复错误；清理无用 import |
| `src/hyqagent/scanner/orchestrator.py` | Provider 初始化失败时增加 structlog 告警 |

## 实现过程

### 根因定位
通过编写诊断脚本逐层测试，确认了完整的故障链路：

1. 用户按 `.env.openai` 模板配置了 `HYQAGENT_CHEAP_PROVIDER=openai`、`HYQAGENT_OPENAI_BASE_URL=https://api.deepseek.com/v1` 等
2. 但 `.env` 中已存在 `HYQAGENT_DEEPSEEK_API_KEY`（之前 Anthropic-format 使用的同一个 DeepSeek key）
3. 用户没有将 API key 复制到 `HYQAGENT_OPENAI_API_KEY`
4. `orchestrator.py::_create_provider` 调用 `cfg.openai_key` → 抛 `ValueError`
5. `except Exception` 裸捕获 → `self._cheap = None`
6. `self._cheap is None` → `self._router` 永不创建
7. 所有 LLM 阶段检查 `self._cheap is None or self._router is None` → 静默跳过
8. **用户看到的现象**：扫描正常完成，但没有任何 LLM 结果，也没有明显报错

### 修复方案

#### 1. `openai_key` 兜底 `deepseek_key`（config.py）
```python
@property
def openai_key(self) -> str:
    key = self.openai_api_key.get_secret_value()
    if not key:
        key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        with contextlib.suppress(ValueError):
            key = self.deepseek_key  # ← 新增兜底
    if not key:
        raise ValueError(...)
    return key
```

#### 2. 重试策略修复（openai_provider.py）
原来的 `@retry` 对所有 `APIStatusError` 都重试，包括 401/400/404 等永远不可恢复的错误：
```python
# Before: 所有 APIStatusError 都重试（包括 401 密码错误、404 模型不存在）
retry=retry_if_exception_type((RateLimitError, ConnectionError, TimeoutError))
| retry_if_exception_type(APIStatusError)

# After: 仅对可恢复错误重试
retry=retry_if_exception_type((RateLimitError, ConnectionError, TimeoutError))
```
如果 API key 错误，用户会立刻看到 `AuthenticationError` 而非等待 3 次重试后超时。

#### 3. Provider 初始化失败告警（orchestrator.py）
```python
except Exception:
    logger.warning("cheap_provider_init_failed", provider=cfg.cheap_provider, exc_info=True)
    self._cheap = None
```
之前静默捕获异常，用户排查困难。现在 structlog 会输出告警。

### 实际 API 测试验证
```python
# 只用 HYQAGENT_DEEPSEEK_API_KEY，不设 HYQAGENT_OPENAI_API_KEY
provider = OpenAIProvider(
    OpenAIConfig(api_key=cfg.openai_key, base_url="https://api.deepseek.com/v1")
)
result = await provider.generate(
    messages=[{"role": "user", "content": "Say hello in one word."}],
    model="deepseek-chat",
)
# → SUCCESS: "hello" (input_tokens=18, output_tokens=1, latency=816ms)
```

`generate_structured` 路径同样验证通过（通过 function-calling 强制结构化输出）。

## 遇到的问题与修复
| 现象 | 原因 | 修复 |
|------|------|------|
| OpenAI 模式 LLM 调用不通，无报错 | `openai_key` 不兜底 `deepseek_key`，异常被静默吞掉 | `openai_key` 属性增加兜底；orchestrator 加告警日志 |
| API key 错误时重试 3 次才报错 | tenacity 对所有 `APIStatusError`（含 401/400）都重试 | 仅对 `RateLimitError/ConnectionError/TimeoutError` 重试 |
| ruff 报 SIM105/F401/E501 | `try-except-pass` 未用 suppress、无用 import、行过长 | 逐一修复 |

## 质量门禁
- ruff (changed files): **All checks passed**
- pytest (1495 tests): **1493 passed, 2 skipped, 0 failures**

## 设计反思
- **做得好**：兜底策略比要求用户复制 API key 友好得多；用 `contextlib.suppress` 而非 `try-except-pass` 语义更清晰
- **遗留问题**：orchestrator.py 中的 `except Exception: self._cheap = None` 仍然是裸捕获——虽然现在加了日志告警，但应区分「配置错误」（应 fail fast）和「网络/API 异常」（可降级）。后续可引入 `ConfigurationError` vs `RuntimeError` 分类

## 下步衔接
- 无阻塞项。OpenAI Provider 的基础调用路径已验证通过，`generate_structured`（finding verification 实际使用的方法）同样正常
- 后续如果在真实扫描中遇到 tool-calling 相关问题，重点排查 `_normalize_tools` 和 `tool_choice` 转换逻辑
