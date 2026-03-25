"""
缺陷报告工具

正式记录缺陷的唯一方式，确保缺陷报告的规范性和完整性。
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from .base import AgentTool, ToolResult

logger = logging.getLogger(__name__)


class VulnerabilityReportInput(BaseModel):
    """缺陷报告输入参数（字段名保持兼容）"""
    title: str = Field(..., description="缺陷标题")
    vulnerability_type: str = Field(
        ..., 
        description="缺陷类型: null_pointer, unhandled_exception, resource_leak, n_plus_one_query, deadlock, oom, performance_issue, concurrency_issue, etc."
    )
    severity: str = Field(
        ..., 
        description="严重程度: critical, high, medium, low, info"
    )
    description: str = Field(..., description="缺陷详细描述")
    file_path: str = Field(..., description="缺陷所在文件路径")
    line_start: Optional[int] = Field(default=None, description="起始行号")
    line_end: Optional[int] = Field(default=None, description="结束行号")
    code_snippet: Optional[str] = Field(default=None, description="相关代码片段")
    source: Optional[str] = Field(default=None, description="污点来源（用户输入点）")
    sink: Optional[str] = Field(default=None, description="危险函数（漏洞触发点）")
    poc: Optional[str] = Field(default=None, description="概念验证/利用方法")
    impact: Optional[str] = Field(default=None, description="影响分析")
    recommendation: Optional[str] = Field(default=None, description="修复建议")
    confidence: float = Field(default=0.8, description="置信度 0.0-1.0")
    cwe_id: Optional[str] = Field(default=None, description="CWE编号")
    cvss_score: Optional[float] = Field(default=None, description="CVSS评分")


class CreateVulnerabilityReportTool(AgentTool):
    """
    创建缺陷报告工具（工具名保持兼容）

    这是正式记录缺陷的唯一方式。只有通过这个工具创建的缺陷才会被计入最终报告。
    这个设计确保了缺陷报告的规范性和完整性。

    通常只有专门的报告Agent或验证Agent才会调用这个工具，
    确保缺陷在被正式报告之前已经经过了充分的验证。

    🔥 v2.1: 添加文件路径验证，拒绝报告不存在的文件
    """

    # 存储所有报告的漏洞
    _vulnerability_reports: List[Dict[str, Any]] = []

    def __init__(self, project_root: Optional[str] = None):
        super().__init__()
        self._reports: List[Dict[str, Any]] = []
        self.project_root = project_root  # 🔥 v2.1: 用于文件验证
    
    @property
    def name(self) -> str:
        return "create_vulnerability_report"
    
    @property
    def description(self) -> str:
        return """创建正式的缺陷报告。这是记录已确认缺陷的唯一方式。

只有在以下情况下才应该使用此工具：
1. 缺陷已经过充分分析和验证
2. 有明确的证据支持缺陷存在
3. 已经评估了缺陷的影响

必需参数:
- title: 缺陷标题
- vulnerability_type: 缺陷类型
- severity: 严重程度 (critical/high/medium/low/info)
- description: 详细描述
- file_path: 文件路径

可选参数:
- line_start/line_end: 行号范围
- code_snippet: 代码片段
- source/sink: 数据流信息
- poc: 概念验证
- impact: 影响分析
- recommendation: 修复建议
- confidence: 置信度
- cwe_id: CWE编号
- cvss_score: CVSS评分"""
    
    @property
    def args_schema(self):
        return VulnerabilityReportInput
    
    async def _execute(
        self,
        title: str,
        vulnerability_type: str,
        severity: str,
        description: str,
        file_path: str,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        code_snippet: Optional[str] = None,
        source: Optional[str] = None,
        sink: Optional[str] = None,
        poc: Optional[str] = None,
        impact: Optional[str] = None,
        recommendation: Optional[str] = None,
        confidence: float = 0.8,
        cwe_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        **kwargs
    ) -> ToolResult:
        """创建缺陷报告"""
        
        # 验证必需字段
        if not title or not title.strip():
            return ToolResult(success=False, error="标题不能为空")
        
        if not description or not description.strip():
            return ToolResult(success=False, error="描述不能为空")
        
        if not file_path or not file_path.strip():
            return ToolResult(success=False, error="文件路径不能为空")

        # 🔥 v2.1: 验证文件路径存在性 - 防止幻觉
        if self.project_root:
            # 清理路径（移除可能的行号，如 "app.py:36"）
            clean_path = file_path.split(":")[0].strip() if ":" in file_path else file_path.strip()
            full_path = os.path.join(self.project_root, clean_path)

            if not os.path.isfile(full_path):
                # 尝试作为绝对路径
                if not (os.path.isabs(clean_path) and os.path.isfile(clean_path)):
                    logger.warning(f"[ReportTool] 🚫 拒绝报告: 文件不存在 '{file_path}'")
                    return ToolResult(
                        success=False,
                        error=f"无法创建报告：文件 '{file_path}' 在项目中不存在。"
                              f"请先使用 read_file 工具验证文件存在，然后再报告缺陷。"
                    )

        # 验证严重程度
        valid_severities = ["critical", "high", "medium", "low", "info"]
        severity = severity.lower()
        if severity not in valid_severities:
            return ToolResult(
                success=False, 
                error=f"无效的严重程度 '{severity}'，必须是: {', '.join(valid_severities)}"
            )
        
        # 验证缺陷类型（字段名保持 vulnerability_type 兼容）
        valid_types = [
            "null_pointer", "unhandled_exception", "resource_leak",
            "infinite_recursion", "deadlock", "oom",
            "n_plus_one_query", "remote_call_in_loop", "unbounded_query",
            "lock_granularity", "unsafe_collection", "unbounded_queue",
            "performance_issue", "concurrency_issue", "memory_issue",
            "other"
        ]
        vulnerability_type = vulnerability_type.lower()
        if vulnerability_type not in valid_types:
            # 允许未知类型，但记录警告
            logger.warning(f"Unknown vulnerability type: {vulnerability_type}")
        
        # 验证置信度
        confidence = max(0.0, min(1.0, confidence))
        
        # 生成报告ID
        report_id = f"defect_{uuid.uuid4().hex[:8]}"
        
        # 构建报告
        report = {
            "id": report_id,
            "title": title.strip(),
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "description": description.strip(),
            "file_path": file_path.strip(),
            "line_start": line_start,
            "line_end": line_end,
            "code_snippet": code_snippet,
            "source": source,
            "sink": sink,
            "poc": poc,
            "impact": impact,
            "recommendation": recommendation or self._get_default_recommendation(vulnerability_type),
            "confidence": confidence,
            "cwe_id": cwe_id,
            "cvss_score": cvss_score,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_verified": True,  # 通过此工具创建的都视为已验证
        }
        
        # 存储报告
        self._reports.append(report)
        CreateVulnerabilityReportTool._vulnerability_reports.append(report)
        
        logger.info(f"Created vulnerability report: [{severity.upper()}] {title}")
        
        # 返回结果
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }.get(severity, "⚪")
        
        return ToolResult(
            success=True,
            data={
                "message": f"缺陷报告已创建: {severity_emoji} [{severity.upper()}] {title}",
                "report_id": report_id,
                "severity": severity,
            },
            metadata=report,
        )
    
    def _get_default_recommendation(self, vuln_type: str) -> str:
        """获取默认修复建议"""
        recommendations = {
            "null_pointer": "在使用对象前进行空值检查，使用 Optional 或空对象模式。",
            "unhandled_exception": "补全异常处理逻辑，避免空 catch，必要时记录日志并上报。",
            "resource_leak": "使用 try-with-resources (Java) 或 with 语句 (Python) 确保资源释放。",
            "n_plus_one_query": "避免循环内单条查询，使用批量查询或 JOIN 优化。",
            "remote_call_in_loop": "合并批量调用，或使用异步并行请求减少累计耗时。",
            "unbounded_query": "添加 LIMIT/分页参数，限制单次查询数据量。",
            "unsafe_collection": "并发场景使用线程安全集合（ConcurrentHashMap 等）或加锁保护。",
            "unbounded_queue": "为线程池队列设置容量上限，并配置拒绝策略。",
            "deadlock": "统一锁获取顺序，避免嵌套锁，必要时使用 tryLock+超时。",
            "oom": "限制集合/缓存大小，避免循环中创建大对象，优化内存占用。",
        }
        return recommendations.get(vuln_type, "请根据具体情况修复此代码缺陷")
    
    def get_reports(self) -> List[Dict[str, Any]]:
        """获取所有报告"""
        return self._reports.copy()
    
    @classmethod
    def get_all_reports(cls) -> List[Dict[str, Any]]:
        """获取所有实例的报告"""
        return cls._vulnerability_reports.copy()
    
    @classmethod
    def clear_all_reports(cls) -> None:
        """清空所有报告"""
        cls._vulnerability_reports.clear()
