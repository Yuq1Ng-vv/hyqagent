"""
core/state.py — Agent 状态类型定义

定义审计过程中流转的状态结构。
LangGraph 的 StateGraph 使用此 TypedDict 作为节点间的状态载体。
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict
from operator import add


class AuditState(TypedDict, total=False):
    """LangGraph 审计流程的状态载体

    字段按照"谁写入、谁读取"分组。
    """

    # ─── 会话元数据 ───
    session_id: str
    target_path: str
    language: str  # python | javascript | java
    framework: str  # flask | django | express | spring | auto
    mode: str  # quick | standard | deep

    # ─── Phase 1 产出 ───
    files_to_analyze: list[str]  # Orchestrator 决定的待分析文件列表
    cpg_built: bool  # CPG 构建是否完成

    # ─── Phase 2-3 产出 ───
    endpoints_mapped: int  # 已分类的端点数量
    hypotheses_generated: int  # 已生成的假设数

    # ─── Phase 4 产出 ───
    findings: Annotated[list[dict[str, Any]], add]  # 跨节点累积的发现
    confirmed_count: int  # 已确认的漏洞数
    rejected_count: int  # 已拒绝的假设数

    # ─── 流程控制 ───
    current_phase: str
    current_file_index: int
    audit_complete: bool
    error_count: int
    messages: list[dict[str, Any]]  # LLM 对话历史
