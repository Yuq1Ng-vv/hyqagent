# HyqAgent: 白盒代码审计Agent CLI工具 — 完整设计方案

## Context

构建一个基于多模型级联的CLI白盒代码审计工具。核心目标：**让单Agent+工具的组合达到接近多Agent的检出率，同时保持单Agent的成本优势**。优先支持 Web 应用漏洞（SQL注入、XSS、SSRF、IDOR、路径穿越等），目标语言 Python/JavaScript/Java。

## 一、核心设计思想（为什么这样设计）

### 1.1 "单Agent + 丰富工具 > 多Agent + 协调开销" 

所有的研究数据都指向同一个结论：盲目的多Agent架构并不会带来更好的结果。MAS-Central和MAS-Decent甚至不如单Agent。只有MAS-Indep（三个Agent完全独立工作、零协调）才勉强超越了SAS，但成本是3倍。

真正的杠杆点不是"更多Agent"，而是"更好的工具"——尤其是**CPG**。

所以我们的架构是：**一个主Agent + CPG查询引擎 + 确定性规则引擎 + 分层验证器**。Agent不直接读代码，而是通过CPG按需提取相关切片。这样既解决了上下文窗口问题，又获得了结构化的精确分析能力。

### 1.2 "提出者≠裁决者" —— 检察官与法官分离

这是从 OpenHack 项目学到的最重要的工程原则。生成漏洞假设的Agent和验证漏洞的Agent必须是不同的——最好用不同的模型。这不是为了"多Agent协作"，而是为了防止确认偏见。

### 1.3 "确定性先行，LLM后行"

不要在可以用正则/tree-sitter/CPG确定的事情上花LLM的钱。比如：找所有`eval()`调用、检查是否有HTTP端点缺少认证注解、追踪一个变量是否真的能从request传到SQL查询——这些都是确定性操作。

### 1.4 模型级联的经济学

对于分类/摘要类任务（如识别API端点功能），便宜模型就够了。对于假设生成（需要语义理解），中等模型。对于最终验证（需要精确推理），强模型。我们的路由策略让90%的token消耗在便宜模型上，10%在强模型上。

---

## 二、整体架构

```
                          hyqagent scan /path/to/repo
                                    │
                    ┌───────────────▼────────────────┐
                    │       CLI Layer (click)         │
                    │  init / scan / resume / report  │
                    └───────────────┬────────────────┘
                                    │
                    ┌───────────────▼────────────────┐
                    │     Session Manager             │
                    │  SQLite 持久化 + 假设生命周期     │
                    │  + 断点续扫 + 证据链存储         │
                    └───────────────┬────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│  CPG Engine  │          │  Scan Engine  │          │ Model Router │
│ tree-sitter  │          │ Deterministic │          │ cheap → mid  │
│ + NetworkX   │◄────────▶│ + Hypothesis  │◄────────▶│ → strong     │
│ + SQLite     │          │ + Validator   │          │ 按任务路由    │
└──────────────┘          └──────────────┘          └──────────────┘
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │        Report Generator        │
                    │  JSON / Markdown / SARIF       │
                    └───────────────────────────────┘
```

---

## 三、CPG Engine — 整个系统的基石

这是最重要的组件，也是投入最多工程精力的地方。

### 3.1 为什么CPG而非直接读代码？

一个简单的例子说明问题：

```
# file: app/routes/user.py
user_input = request.args.get('name')  # source

# file: app/services/search.py  
query = build_query(user_input)        # propagation
cursor.execute(query)                   # sink
```

如果直接把这三个文件的内容塞进LLM的prompt，模型需要自己"看出"数据流关系。对于小项目这能work，但对于100+文件的真实项目，这不可能。

有了CPG，LLM只需要做：`cpq_query("从 routes/user.py:name 到 services/search.py:cursor.execute 的路径")` ——得到精确的污点传播路径，然后基于这个路径做判断。

### 3.2 CPG的构成

```python
# 五种图，存储在同一个 NetworkX MultiDiGraph 中
# 每种关系用不同的边类型标记

class CPGEdge:
    AST_EDGE = "ast"           # 语法父子关系
    CALLS = "calls"            # 函数A调用了函数B
    DATA_FLOW = "data_flow"    # 数据从表达式A流向表达式B  
    CONTROL_FLOW = "ctrl_flow" # 控制流（if/then/else, loop）
    HTTP_ROUTE = "http_route"  # HTTP路由信息
```

### 3.3 构建流程

```
Step 1: tree-sitter 解析每个源文件 → 原始AST
Step 2: 从AST提取函数、类、导入、路由等结构化信息
Step 3: 构建调用图（resolve imports → cross-file call edges）
Step 4: 构建数据流图（def-use chains, taint propagation）
Step 5: 框架特定提取器识别HTTP入口点
Step 6: 持久化到 SQLite（metadata）+ pickle（图结构）
```

### 3.4 框架特定提取器

这是Web应用审计的关键。不同框架的路由声明方式完全不同：

```python
# Flask
@app.route('/users/<id>', methods=['GET'])
def get_user(id): ...

# FastAPI
@app.get("/users/{id}")
async def get_user(id: int): ...

# Express
app.get('/users/:id', (req, res) => { ... })

# Spring
@GetMapping("/users/{id}")
public User getUser(@PathVariable Long id) { ... }
```

每种框架需要一个提取器，识别路由模式、提取参数、标记HTTP方法和路径。这些提取器是纯确定性的——用tree-sitter或正则即可，不需要LLM。

### 3.5 污点源和污点汇的定义

```python
# 从配置文件读取，可扩展
TAINT_SOURCES = {
    "python": [
        "request.args.get", "request.form.get", "request.json",
        "request.headers.get", "request.cookies.get",
        "request.get_json()", "request.data",
        "flask.request.*", "fastapi.Request.*"
    ],
    "javascript": [
        "req.body.*", "req.query.*", "req.params.*",
        "req.headers[*]", "req.cookies.*",
        "req.url", "req.path"
    ],
    "java": [
        "@RequestParam", "@PathVariable", "@RequestBody",
        "HttpServletRequest.getParameter",
        "HttpServletRequest.getHeader"
    ]
}

TAINT_SINKS = {
    "sql_injection": [
        "cursor.execute", "session.execute", "connection.execute",
        "cursor.executemany", "Session.query",
        # JS: "pool.query", "db.query", "knex.raw"
        # Java: "jdbcTemplate.query", "entityManager.createQuery"
    ],
    "xss": [
        "render_template", "Response(..., mimetype='text/html')",
        # JS: "res.send", "res.render", "innerHTML"
    ],
    "ssrf": [
        "requests.get", "urllib.request.urlopen", "httpx.get",
        # JS: "axios.get", "fetch", "http.get"
    ],
    "command_injection": [
        "os.system", "subprocess.call", "subprocess.Popen",
        # JS: "child_process.exec", "child_process.spawn"
    ],
    "path_traversal": [
        "open(", "Path(", "os.path.join",
        # JS: "fs.readFile", "fs.createReadStream"
    ],
    "deserialization": [
        "pickle.load", "yaml.load", "marshal.load",
        # JS: "eval(", "new Function("
        # Java: "ObjectInputStream.readObject"
    ]
}
```

### 3.6 CPG查询接口

```python
class CPGQuery:
    def find_path(self, source_node, sink_node) -> List[Path]:
        """找出从source到sink的所有数据流路径"""
    
    def find_sources(self, sink_node) -> List[Node]:
        """找出所有流向sink的数据源"""
    
    def find_sinks(self, source_node) -> List[Node]:
        """从source出发，找出所有可达的危险sink"""
    
    def get_sanitizers(self, path: Path) -> List[Node]:
        """检查路径上是否存在消毒/验证函数"""
    
    def get_call_chain(self, func_a, func_b) -> Optional[Path]:
        """获取函数A到函数B的调用链"""
```

---

## 四、Scan Engine — 扫描流水线

### 4.1 整体流程（5个阶段）

```
Phase 1: Deterministic Pre-scan    ← 0 LLM tokens, 纯规则
Phase 2: Attack Surface Mapping    ← cheap model (Kimi/GLM)
Phase 3: Hypothesis Generation     ← mid model (Sonnet)  
Phase 4: Validation                ← strong model (Opus/GPT-5.2)
Phase 5: Report Assembly           ← 0 LLM tokens, 纯组装
```

### 4.2 Phase 1: Deterministic Pre-scan

**目标**：用零LLM成本捕获所有"确定性可检测"的漏洞。

**具体规则**：
```python
# 规则1: 硬编码密钥/密码
# 正则: password\s*=\s*['"][^'"]+['"] 
# 正则: api_key\s*=\s*['"][^'"]+['"]

# 规则2: 明确的危险调用
# eval(、exec(、os.system(、subprocess.call( 等

# 规则3: CPG污点追踪 — 无消毒的source→sink路径
# 如果CPG显示: request.args.get → ... → cursor.execute
# 且中间没有任何 sanitize/validate/parameterize → 直接标记

# 规则4: 缺失认证注解
# 检测有 @app.route 但没有 @login_required 或类似装饰器的端点

# 规则5: 调试模式/不安全配置
# DEBUG=True, SECRET_KEY='dev', CORS allow_origin='*'
```

### 4.3 Phase 2: Attack Surface Mapping

**目标**：用便宜模型分类每个API端点的功能和风险。

**为什么需要LLM**：确定性的路由提取可以拿到`/api/admin/users/:id`这样的路径，但要判断"这个接口是管理员删用户用的"还是"普通用户看自己资料的"，需要语义理解。这个判断不需要100%准确，便宜模型足够。

**具体做法**：
```
对于每个提取出的HTTP端点:
  1. 从CPG获取端点处理函数的代码（仅函数体 + 直接调用的函数签名）
  2. 构造prompt让便宜模型回答:
     { 
       "function": "认证/授权/数据查询/数据修改/文件操作/管理功能/公开接口",
       "trust_boundary": "外部用户/内部服务/管理员/无需认证",
       "data_sensitivity": "PII/密码/支付/内部数据/公开数据/无数据",
       "priority": 1-10
     }
  3. 按priority排序，只对priority >= 5的端点进入Phase 3
```

**成本估算**：一个中型项目（200个API端点），每个分类用100个output token，总共~20K output tokens。用Kimi K2（$0.50/1M output）= $0.01。

### 4.4 Phase 3: Hypothesis Generation

**目标**：为每个高优先级端点生成漏洞假设。

**核心创新——CPG切片提示（不是全量代码提示）**：
```python
def generate_hypothesis_prompt(endpoint, cpg):
    # Step 1: 用CPG找出该端点所有用户输入的去向
    sources = cpg.find_sources_for_endpoint(endpoint)
    
    # Step 2: 对每个source，追踪到最近的危险sink
    for source in sources:
        paths = cpg.find_sinks(source)
        for path in paths:
            # Step 3: 提取路径上的关键节点代码（仅相关行！）
            # 不是整个函数，而是路径经过的具体语句
            sliced_code = cpg.slice_path(path, context_lines=3)
            
            # Step 4: 检查路径上是否有消毒
            sanitizers = cpg.get_sanitizers(path)
    
    # Step 5: 组装结构化的分析提示
    prompt = f"""
    分析以下代码中是否存在安全漏洞。
    
    ## 端点信息
    路径: {endpoint.route}
    HTTP方法: {endpoint.methods}
    
    ## 数据流路径
    用户输入: {source.code_snippet} (位置: {source.file}:{source.line})
        ↓
    {format_data_flow_steps(sliced_code)}
        ↓
    危险操作: {sink.code_snippet} (位置: {sink.file}:{sink.line})
    
    ## 检测到的消毒措施
    {format_sanitizers(sanitizers)}  # 如果有的话
    
    ## 要求
    请判断此路径是否存在可利用的漏洞。如果存在，输出：
    1. 漏洞类型 (CWE编号)
    2. 可利用性评估 (确信/可能/不太可能)
    3. 攻击场景描述
    4. 需要进一步验证的关键条件
    
    如果不存在漏洞，说明为什么此路径是安全的。
    """
    
    # 关键是：prompt中只包含相关代码，不是整个文件！
    return prompt
```

**为什么用中等模型**：假设生成需要语义理解（"这段代码的意图是什么"），这是模型的核心能力。但因为我们只需要"假设"而非"定论"，中等模型的精度足够。Sonnet在代码理解上的能力是Opus的~85%，但成本是1/3。

### 4.5 Phase 4: Validation

**验证的两个层次**：

**L1: 确定性验证（零LLM成本）**
```python
def deterministic_validate(hypothesis, cpg):
    # 1. 验证数据流路径真实存在
    actual_path = cpg.find_path(
        hypothesis.source_location, 
        hypothesis.sink_location
    )
    if not actual_path:
        return ValidationResult.REJECTED, "数据流路径不存在"
    
    # 2. 验证source/sink类型匹配
    if not cpg.is_sink_type(hypothesis.sink, hypothesis.vuln_type):
        return ValidationResult.REJECTED, "Sink类型与漏洞类型不匹配"
    
    # 3. 验证行号/代码片段与假设中的一致
    actual_code = cpg.get_code(hypothesis.source_location)
    if not code_matches(hypothesis.source_snippet, actual_code):
        return ValidationResult.REJECTED, "代码片段不匹配（文件已变更？）"
    
    return ValidationResult.PASSED_DETERMINISTIC
```

**L2: LLM验证（强模型）**
```python
def llm_validate(hypothesis, cpg):
    # 获取完整路径上下文（比Phase 3更详细）
    full_path_context = cpg.get_full_path_context(
        hypothesis.source,
        hypothesis.sink,
        include_sanitizers=True,
        include_related_tests=True,  # 相关单元测试可以提供额外证据
        context_window=8000,         # 更多上下文给强模型
    )
    
    prompt = f"""
    作为安全审计专家，请严格验证以下漏洞假设。

    ## 假设
    漏洞类型: {hypothesis.vuln_type}
    严重程度(初步): {hypothesis.severity}
    数据流路径: (从source到sink的完整路径，带行号)

    ## 你需要判断
    1. 数据流路径是否真实且可达？
    2. 路径上的条件检查是否可以被绕过？
    3. 是否存在有效的消毒/验证措施？它们是否充分？
    4. 是否存在框架级保护？（如ORM自动参数化、模板引擎自动转义）
    5. 综合考虑以上因素，此漏洞是否真实可用？
    
    ## 输出格式
    {{
      "verdict": "CONFIRMED" | "REJECTED" | "INCONCLUSIVE",
      "confidence": 0.0-1.0,
      "reasoning": "详细的推理过程，逐条回应上述5个问题",
      "critical_conditions": ["如果需要额外条件才能利用，列在这里"],
      "rejection_reason": "如果REJECTED，说明为什么假设不成立"
    }}
    """
```

**为什么L1+L2两层验证**：L1过滤掉明显的误报（路径不存在的、代码对不上的），这些占Phase 3产出的约30-40%。剩下的才用强模型验证，大幅节省成本。

### 4.6 Phase 5: Report Assembly

```
确认的漏洞 → 按严重程度排序 → 生成报告

每个确认漏洞的输出:
{
  "id": "HYQ-2026-0001",
  "title": "SQL Injection in /api/users/search",
  "cwe": "CWE-89",
  "severity": "CRITICAL",
  "confidence": 0.92,
  "location": {
    "source": {"file": "routes/user.py", "line": 42, "function": "search_users"},
    "sink": {"file": "services/db.py", "line": 18, "function": "query"}
  },
  "data_flow": [
    {"step": 1, "location": "routes/user.py:42", "code": "name = request.args.get('name')", "role": "source"},
    {"step": 2, "location": "routes/user.py:44", "code": "results = db.search(name)", "role": "call"},
    {"step": 3, "location": "services/db.py:17", "code": "query = f\"SELECT * FROM users WHERE name='{name}'\"", "role": "propagation"},
    {"step": 4, "location": "services/db.py:18", "code": "cursor.execute(query)", "role": "sink"}
  ],
  "evidence_chain": {
    "deterministic": "CPG confirmed path reachability",
    "llm_validation": "Opus confirmed no sanitization, f-string directly concatenated",
    "poc_feasibility": "Single quote injection confirmed possible via input parameter"
  },
  "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name=?', (name,))",
  "validation_history": [
    {"stage": "phase1_deterministic", "result": "flagged"},
    {"stage": "phase3_hypothesis", "model": "sonnet-4.6", "result": "suspected_sqli"},
    {"stage": "phase4_l1", "result": "path_confirmed"},
    {"stage": "phase4_l2", "model": "opus-4.6", "result": "confirmed", "confidence": 0.92}
  ]
}
```

---

## 五、Session Manager — 持久化与信念系统

### 5.1 SQLite Schema

```sql
-- 会话表
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    branch TEXT,
    commit_hash TEXT,
    status TEXT DEFAULT 'initializing',
    config JSON,
    stats JSON,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 文件索引（支持增量扫描）
CREATE TABLE file_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT REFERENCES sessions(id),
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,  -- SHA256，用于检测变更
    language TEXT,
    loc INTEGER,
    parsed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CPG节点索引
CREATE TABLE cpg_nodes (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id),
    node_type TEXT,  -- function, class, variable, http_endpoint, import
    name TEXT,
    file_path TEXT,
    start_line INTEGER,
    end_line INTEGER,
    metadata JSON
);

-- 漏洞假设
CREATE TABLE hypotheses (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id),
    status TEXT DEFAULT 'proposed',
    -- proposed → investigating → l1_validated → llm_validated → confirmed → reported
    --                                                    ↘ rejected (停止追踪)
    --                                                    ↘ inconclusive (等待更多证据)
    vuln_type TEXT,
    cwe_id TEXT,
    severity TEXT,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence REAL,  -- 0.0 - 1.0, 贝叶斯更新
    title TEXT,
    description TEXT,
    
    -- 位置信息
    source_file TEXT,
    source_line INTEGER,
    source_function TEXT,
    sink_file TEXT,
    sink_line INTEGER,
    sink_function TEXT,
    
    -- 证据
    data_flow_path JSON,   -- [{step, file, line, code, role}, ...]
    evidence_chain JSON,   -- [{type, result, details, timestamp}, ...]
    
    -- 元数据
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    validated_at TIMESTAMP,
    confirmed_at TIMESTAMP
);

-- 验证记录
CREATE TABLE validations (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT REFERENCES hypotheses(id),
    validation_type TEXT,  -- l1_deterministic, l2_llm_static, l3_sandbox_poc
    model TEXT,            -- 如果用LLM的话
    verdict TEXT,          -- passed, rejected, inconclusive
    confidence_delta REAL, -- 这次验证对假设置信度的影响
    reasoning TEXT,
    evidence JSON,
    tokens_used INTEGER,
    cost REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 模型调用日志（成本追踪）
CREATE TABLE model_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT REFERENCES sessions(id),
    phase TEXT,
    model TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost REAL,
    latency_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 5.2 信念系统的实现

```python
class BeliefSystem:
    """
    管理漏洞假设的生命周期。
    不是简单的 boolean，而是一个状态机 + 贝叶斯置信度更新。
    """
    
    STATUS_TRANSITIONS = {
        'proposed': ['investigating', 'rejected'],
        'investigating': ['l1_validated', 'rejected'],
        'l1_validated': ['l2_validated', 'rejected'],
        'l2_validated': ['confirmed', 'rejected', 'inconclusive'],
        'confirmed': ['reported'],
        'reported': [],  # 终态
        'rejected': [],  # 终态
        'inconclusive': ['investigating'],  # 可以重新调查
    }
    
    def update_confidence(self, hypothesis, evidence, evidence_strength):
        """
        贝叶斯更新：
        P(vuln|evidence) = P(evidence|vuln) * P(vuln) / P(evidence)
        
        简化实现：
        - confirming evidence: confidence *= (1 + strength * (1 - confidence))
        - refuting evidence:   confidence *= (1 - strength * confidence)
        """
        if evidence.verdict == 'supporting':
            hypothesis.confidence += evidence_strength * (1 - hypothesis.confidence)
        else:
            hypothesis.confidence *= (1 - evidence_strength * hypothesis.confidence)
        
        # 确保在 [0, 1] 范围内
        hypothesis.confidence = max(0.0, min(1.0, hypothesis.confidence))
```

---

## 六、Model Router — 多模型级联

### 6.1 路由策略

```python
class ModelRouter:
    """
    按任务类型和复杂度路由到不同模型。
    
    模型分三档：
    - CHEAP: Kimi K2 Instruct ($0.50/1M in+out) 或 GLM-5.1 ($1.06/PR)
    - MID: Claude Sonnet 4.6 ($3/$15 per 1M in/out)
    - STRONG: Claude Opus 4.6 ($15/$75 per 1M in/out)
    
    成本比: cheap:mid:strong = 1:30:150
    """
    
    CHEAP_MODELS = ["kimi-k2-instruct", "glm-5.1"]
    MID_MODELS = ["claude-sonnet-4-6"]
    STRONG_MODELS = ["claude-opus-4-6", "gpt-5.2"]
    
    def route(self, task: Task) -> ModelSpec:
        """
        路由决策矩阵：
        
        Task Type            → Model Tier   Reasoning
        ─────────────────────────────────────────────
        代码分类/摘要        → CHEAP        结构化输出，不需要深度推理
        攻击面分析           → CHEAP        模式识别，便宜模型够用
        假设生成（简单路径）  → CHEAP        路径短、逻辑直白的
        假设生成（复杂路径）  → MID          跨文件、多跳、需要业务理解
        假设生成（逻辑漏洞）  → STRONG       需要深层语义推理
        确定性验证(L1)       → 无LLM        纯CPG查询
        LLM验证(L2，中置信)  → MID          假设置信度40-70%
        LLM验证(L2，高价值)  → STRONG       假设置信度>70%且severity≥HIGH
        """
        
        if task.type == TaskType.CLASSIFICATION:
            return self._pick_cheapest_available()
        
        if task.type == TaskType.HYPOTHESIS:
            complexity = self._assess_complexity(task)
            if complexity < 3:
                return self._pick_cheapest_available()
            elif complexity < 7:
                return self._pick_available(self.MID_MODELS)
            else:
                return self._pick_available(self.STRONG_MODELS)
        
        if task.type == TaskType.VALIDATION:
            hypothesis = task.context['hypothesis']
            if hypothesis.confidence > 0.7 and hypothesis.severity in ['CRITICAL', 'HIGH']:
                return self._pick_available(self.STRONG_MODELS)
            else:
                return self._pick_available(self.MID_MODELS)
    
    def _assess_complexity(self, task) -> int:
        """
        复杂度评分 1-10：
        - 数据流跳数 (source→sink步数): 每步+1
        - 跨文件: +2
        - 跨模块/包: +3
        - 涉及异步/回调: +1
        - 涉及反射/动态调用: +2
        - 路径上有循环: +1
        """
        score = 0
        path = task.context.get('data_flow_path', [])
        score += min(len(path), 5)  # 最多+5
        
        files = set(step.file for step in path)
        score += min(len(files) - 1, 2) * 2  # 跨文件最多+4
        
        if task.context.get('has_async'):
            score += 1
        if task.context.get('has_reflection'):
            score += 2
        
        return min(score, 10)
```

### 6.2 成本控制

```python
class BudgetManager:
    """
    成本控制三层机制：
    1. 总预算上限 (--max-cost $X)
    2. 每阶段预算比例  
    3. 自动降级 (超出预算时从STRONG降级到MID)
    """
    
    DEFAULT_BUDGET = 5.0  # 默认每个项目$5
    DEFAULT_ALLOCATION = {
        'phase2_mapping': 0.05,    # 攻击面映射: 5%，几乎免费
        'phase3_hypothesis': 0.30,  # 假设生成: 30%
        'phase4_l2_validation': 0.60, # LLM验证: 60%（大头）
        'misc': 0.05,               # 其他: 5%
    }
    
    def check_and_route(self, task, remaining_budget):
        """在预算不足时自动降级模型选择"""
        proposed_model = self.router.route(task)
        estimated_cost = self.estimate_cost(task, proposed_model)
        
        if estimated_cost <= remaining_budget:
            return proposed_model
        
        # 降级策略
        if proposed_model.tier == 'STRONG':
            fallback = self.router.MID_MODELS[0]
            if self.estimate_cost(task, fallback) <= remaining_budget:
                logger.warning(f"Budget constraint: downgrading {task.type} from STRONG to MID")
                return fallback
        
        if proposed_model.tier in ('STRONG', 'MID'):
            fallback = self.router.CHEAP_MODELS[0]
            if self.estimate_cost(task, fallback) <= remaining_budget:
                logger.warning(f"Budget constraint: downgrading {task.type} to CHEAP")
                return fallback
        
        # 仍然超出预算，跳过此任务
        logger.warning(f"Skipping {task.type} due to budget exhaustion")
        return None
```

---

## 七、CLI设计

### 7.1 命令结构

```bash
# 初始化配置
hyqagent init
# 生成 ~/.hyqagent/config.yaml

# 快速扫描（SAS模式，单Agent + 规则）
hyqagent scan ./myapp --quick
# 等价于: --mode=sas --max-cost=1.0

# 标准扫描（默认，两阶段验证）
hyqagent scan ./myapp
# 等价于: --mode=standard --max-cost=5.0

# 深度扫描（FULL模式，所有验证层）
hyqagent scan ./myapp --deep
# 等价于: --mode=deep --max-cost=25.0

# 指定语言/框架
hyqagent scan ./myapp --lang python --framework flask

# 只看特定漏洞类型
hyqagent scan ./myapp --vuln-types sqli,xss,ssrf

# 增量扫描（仅扫描变更文件）
hyqagent scan ./myapp --incremental

# 续扫
hyqagent resume <session-id>

# 查看会话
hyqagent sessions list
hyqagent sessions show <session-id>

# 生成报告
hyqagent report <session-id> --format json
hyqagent report <session-id> --format markdown
hyqagent report <session-id> --format sarif

# 配置管理
hyqagent config show
hyqagent config set models.cheap kimi-k2-instruct
hyqagent config set models.mid claude-sonnet-4-6
hyqagent config set models.strong claude-opus-4-6
```

### 7.2 配置文件

```yaml
# ~/.hyqagent/config.yaml
models:
  cheap:
    provider: anthropic  # or openai, local
    model: claude-sonnet-4-6  # 实际用便宜模型时会覆盖
    api_key: ${ANTHROPIC_API_KEY}
  mid:
    provider: anthropic
    model: claude-sonnet-4-6
    api_key: ${ANTHROPIC_API_KEY}
  strong:
    provider: anthropic
    model: claude-opus-4-6
    api_key: ${ANTHROPIC_API_KEY}

scan:
  default_mode: standard
  max_cost_per_project: 5.0
  phase_timeout_seconds:
    cpg_build: 300
    deterministic: 60
    hypothesis: 600
    validation: 900
  parallel_workers: 4

frameworks:
  python:
    - flask
    - django
    - fastapi
  javascript:
    - express
    - nextjs
  java:
    - spring
    - jax-rs

output:
  default_format: markdown
  report_dir: ./hyqagent-reports
  include_evidence: true
  include_remediation: true
```

---

## 八、详细实现路线图

### Phase 1: CPG Foundation（预计工作量：5-7天）

**目标**：能解析代码、构建调用图+数据流图、查询路径

```
Day 1-2: tree-sitter集成
  - 安装 tree-sitter + Python/JS/Java 语法
  - 实现 AST 遍历工具类
  - 支持从 AST 提取函数、类、导入、变量定义

Day 3-4: 调用图构建
  - 解析 import/require，解决跨文件引用
  - 构建 calls 边（函数A调用函数B）
  - 支持方法调用解析（obj.method()）

Day 5: 数据流图构建
  - def-use chain 分析
  - 跨函数数据流追踪（通过参数/返回值）
  - 基础污点传播（变量赋值 → 函数传参 → 返回值）

Day 6-7: 框架提取器 + CPG查询接口
  - Flask/Express/Spring 路由提取器
  - Taint source/sink 配置化注册
  - CPGQuery 查询接口实现
```

**技术选型**：
- `tree-sitter` + Python bindings
- `networkx` 用于图存储和路径查询
- `sqlite3`（标准库）用于元数据持久化

### Phase 2: Deterministic Scanner（预计工作量：3-4天）

**目标**：零LLM成本发现确定性漏洞

```
Day 1-2: 规则引擎
  - 正则规则（硬编码密钥、密码）
  - CPG规则（source→sink无消毒路径）
  - 配置规则（DEBUG=True等）
  
Day 3: 污点追踪引擎
  - 从taint source出发，沿CPG数据流边遍历
  - 遇到sanitizer函数时停止追踪
  - 到达taint sink时生成告警

Day 4: CLI v0
  - hyqagent scan --quick 可用
  - 纯确定性扫描，输出 JSON
```

### Phase 3: LLM Integration（预计工作量：5-7天）

**目标**：多模型级联的假设生成和验证

```
Day 1-2: Model Router + Provider Adapters
  - Anthropic provider (Claude Opus/Sonnet)
  - OpenAI-compatible provider (Kimi/GLM/GPT)
  - 成本追踪

Day 3-4: Hypothesis Generator
  - CPG切片提示构建
  - 漏洞假设结构化输出
  - 复杂度评分

Day 5-6: Validator
  - L1 确定性验证
  - L2 LLM验证（强模型）

Day 7: Session Manager
  - SQLite schema
  - 假设生命周期
```

### Phase 4: Integration & Polish（预计工作量：3-4天）

```
Day 1-2: Report Generator
  - JSON/Markdown/SARIF 输出
  - 证据链组装

Day 3: CLI polish
  - resume/sessions/report 命令
  - 进度显示
  - 错误处理

Day 4: 文档 + 测试
  - 使用文档
  - 集成测试（拿真实开源项目跑）
```

---

## 九、项目目录结构

```
hyqagent/
├── pyproject.toml
├── README.md
│
├── hyqagent/
│   ├── __init__.py
│   ├── cli.py                  # CLI入口
│   ├── config.py               # 配置加载
│   │
│   ├── cpg/                    # CPG Engine
│   │   ├── __init__.py
│   │   ├── builder.py          # CPG构建主流程
│   │   ├── parser.py           # tree-sitter封装
│   │   ├── call_graph.py       # 调用图构建
│   │   ├── data_flow.py        # 数据流+污点追踪
│   │   ├── query.py            # CPG查询接口
│   │   ├── taint_rules.yaml    # Taint source/sink配置
│   │   ├── sanitizers.yaml     # Sanitizer函数配置
│   │   └── frameworks/         # 框架特定提取器
│   │       ├── __init__.py
│   │       ├── flask.py
│   │       ├── django.py
│   │       ├── fastapi.py
│   │       ├── express.py
│   │       └── spring.py
│   │
│   ├── scanner/                # Scan Engine
│   │   ├── __init__.py
│   │   ├── orchestrator.py     # 扫描流水线编排
│   │   ├── deterministic.py    # Phase 1: 确定性规则
│   │   ├── mapper.py           # Phase 2: 攻击面映射
│   │   ├── hypothesis.py       # Phase 3: 假设生成
│   │   ├── validator.py        # Phase 4: 验证 (L1+L2)
│   │   └── rules/              # 确定性规则
│   │       ├── secrets.yaml
│   │       ├── dangerous_calls.yaml
│   │       └── config_issues.yaml
│   │
│   ├── models/                 # Model Router
│   │   ├── __init__.py
│   │   ├── router.py           # 模型路由
│   │   ├── budget.py           # 预算管理
│   │   └── providers/          # LLM Provider适配
│   │       ├── __init__.py
│   │       ├── anthropic.py
│   │       └── openai_compat.py
│   │
│   ├── session/                # Session Manager
│   │   ├── __init__.py
│   │   ├── manager.py          # 会话CRUD
│   │   ├── belief.py           # 信念系统
│   │   └── schema.sql          # 数据库schema
│   │
│   └── report/                 # Report Generator
│       ├── __init__.py
│       ├── json_report.py
│       ├── markdown_report.py
│       └── sarif_report.py
│
└── tests/
    ├── test_cpg/
    │   ├── test_parser.py
    │   ├── test_call_graph.py
    │   ├── test_data_flow.py
    │   └── fixtures/           # 测试用的代码样本
    ├── test_scanner/
    └── test_models/
```

---

## 十、关键开源依赖

| 用途 | 库 | 理由 |
|:---|:---|:---|
| 代码解析 | `tree-sitter` | 最快的通用解析器，支持所有主流语言 |
| 图存储/查询 | `networkx` | Python生态最成熟的图库 |
| CLI框架 | `click` | 比 argparse 更适合CLI工具 |
| LLM接口 | `anthropic` + 自建 openai-compat adapter | 多provider支持 |
| YAML配置 | `pyyaml` | 规则和配置都用YAML |
| 输出格式化 | `rich` | 终端彩色输出、进度条 |
| ORM | 直接用 `sqlite3` | 轻量，不需要SQLAlchemy |

---

## 十一、验证方案

### 端到端测试

```bash
# 1. 用已知漏洞的项目做回归测试
# 使用 OWASP WebGoat, DVWA, VulnPy 等

# 2. 扫描一个已知包含 SQLi 的项目
hyqagent scan ./test-fixtures/sqli-demo --quick
# 预期: 确定性规则应标记 f-string SQL构造

# 3. 扫描一个真实开源项目
hyqagent scan ./test-fixtures/flask-real-app
# 预期: 应在$5预算内完成，产出结构化报告

# 4. 验证CPG精确性
# 已知 source→sink 路径应被准确追踪
# 已知的 sanitized 路径应被正确排除
```

### 质量指标

- CPG构建覆盖率达到 90%+（能解析90%的源文件）
- 确定性规则：0假阳性（因为是确定性的）
- LLM假设：精确率目标 70%+（Phase 3产出经Phase 4过滤前）
- LLM验证后：精确率目标 85%+（类似RepoAudit的78-88%）
- 每个项目平均成本：$3-8（快速模式$0.5-1，标准模式$3-5，深度模式$15-25）
