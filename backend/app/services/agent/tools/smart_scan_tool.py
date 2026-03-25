"""
智能批量扫描工具
整合多种扫描能力，一次性完成多项代码缺陷检查

设计目的：
1. 减少 LLM 需要做的工具调用次数
2. 提供更完整的代码质量概览
3. 自动选择最适合的扫描策略
"""

import os
import re
import asyncio
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from dataclasses import dataclass, field

from .base import AgentTool, ToolResult

logger = logging.getLogger(__name__)


class SmartScanInput(BaseModel):
    """智能扫描输入"""
    target: str = Field(
        default=".",
        description="扫描目标：可以是目录路径、文件路径或文件模式（如 '*.py'）"
    )
    scan_types: Optional[List[str]] = Field(
        default=None,
        description="扫描类型列表。可选: pattern, all。默认为 all"
    )
    focus_defects: Optional[List[str]] = Field(
        default=None,
        description="重点关注的缺陷类型，如 ['resource_leak', 'null_pointer', 'loop_db_query', 'unsafe_collection', 'unbounded_query']"
    )
    max_files: int = Field(default=50, description="最大扫描文件数")
    quick_mode: bool = Field(default=False, description="快速模式：只扫描高风险文件")


class SmartScanTool(AgentTool):
    """
    智能批量扫描工具
    
    自动整合多种扫描能力：
    - 运行缺陷模式匹配 (pattern)
    - 稳定性风险检测
    - 性能隐患检测
    - 并发问题检测
    - 资源泄露检测
    
    特点：
    1. 自动识别项目类型和技术栈
    2. 智能选择最适合的扫描策略
    3. 按风险级别汇总结果
    4. 一次调用完成多项检查
    """
    
    # 高风险文件模式（可能存在运行缺陷的区域）
    HIGH_RISK_PATTERNS = [
        r'.*service.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*dao.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*repository.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*controller.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*handler.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*manager.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*worker.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*task.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*thread.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*pool.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*cache.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*db.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*sql.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*file.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*stream.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*connection.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*batch.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*scheduler.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*queue.*\.(py|js|ts|tsx|jsx|java|php|kt|rs|go)$',
        r'.*config.*\.(py|js|ts|tsx|jsx|json|yaml|yml|xml|properties)$',
    ]
    
    # 运行缺陷模式库（精简版，用于快速扫描）
    QUICK_PATTERNS = {
        "null_pointer": [
            (r'\.\w+\s*\.\w+\s*\.\w+', "深层链式调用（可能NPE）"),
            (r'\.get\s*\([^)]*\)\s*\.', "get后直接调用（可能NPE）"),
            (r'return\s+\w+\.\w+\(\)\.', "返回值链式调用（可能NPE）"),
        ],
        "unhandled_exception": [
            (r'except\s*:\s*$', "空异常捕获"),
            (r'except\s+\w+.*:\s*\n\s*(pass|\.\.\.)', "异常被忽略"),
            (r'catch\s*\(\s*\w+\s+\w+\s*\)\s*\{\s*\}', "空catch块"),
            (r'catch\s*\(\s*Exception', "捕获过宽的异常"),
        ],
        "resource_leak": [
            (r'open\s*\([^)]*\)', "文件打开（检查是否关闭）"),
            (r'new\s+File(?:Input|Output|Reader|Writer)', "Java文件流（检查是否关闭）"),
            (r'DriverManager\.getConnection', "JDBC连接（检查是否关闭）"),
            (r'\.getConnection\s*\(', "数据库连接获取"),
            (r'new\s+(?:Buffered|Input|Output)Stream', "IO流创建（检查是否关闭）"),
            (r'socket\s*\(', "Socket创建（检查是否关闭）"),
            (r'createStatement\s*\(\)', "JDBC Statement（检查是否关闭）"),
        ],
        "loop_db_query": [
            (r'for\s+.*:\s*\n[^}]*(?:execute|query|find|select|fetch)', "循环内数据库查询"),
            (r'while\s+.*:\s*\n[^}]*(?:execute|query|find|select|fetch)', "循环内数据库查询"),
            (r'\.forEach\s*\([^)]*\)\s*(?:->|=>)\s*\{[^}]*(?:query|find|save|delete)', "forEach内数据库操作"),
            (r'for\s*\(.*\)\s*\{[^}]*(?:execute|query|find|select|fetch)', "循环内数据库查询"),
        ],
        "remote_call_in_loop": [
            (r'for\s+.*:\s*\n[^}]*(?:requests\.|http\.|fetch\(|\.get\(|\.post\()', "循环内远程调用"),
            (r'for\s*\(.*\)\s*\{[^}]*(?:HttpClient|RestTemplate|WebClient)', "循环内HTTP调用"),
            (r'\.forEach\s*\([^)]*\)\s*(?:->|=>)\s*\{[^}]*(?:http|fetch|request)', "forEach内远程调用"),
        ],
        "unbounded_query": [
            (r'SELECT\s+\*\s+FROM\s+\w+\s*(?:;|$|")', "无LIMIT的全表查询"),
            (r'\.findAll\s*\(\s*\)', "无条件全量查询"),
            (r'\.find\s*\(\s*\{\s*\}\s*\)', "MongoDB无条件查询"),
            (r'FROM\s+\w+\s+WHERE.*(?:LIKE\s+["\']%)', "LIKE模糊查询（可能全表扫描）"),
        ],
        "unsafe_collection": [
            (r'new\s+HashMap\s*<', "HashMap（非线程安全）"),
            (r'new\s+ArrayList\s*<', "ArrayList（非线程安全）"),
            (r'new\s+HashSet\s*<', "HashSet（非线程安全）"),
            (r'(?:static|shared|global)\s+.*(?:HashMap|ArrayList|HashSet|LinkedList)', "静态非线程安全集合"),
        ],
        "unbounded_thread_pool": [
            (r'Executors\.newCachedThreadPool', "无界线程池"),
            (r'new\s+LinkedBlockingQueue\s*\(\s*\)', "无界队列"),
            (r'Executors\.newFixedThreadPool\s*\(\s*\d{3,}', "线程池过大"),
            (r'new\s+Thread\s*\(', "直接创建线程（未使用线程池）"),
            (r'ThreadLocal\s*<', "ThreadLocal（检查是否remove）"),
        ],
        "infinite_recursion": [
            (r'def\s+(\w+)\s*\([^)]*\):[^}]*\1\s*\(', "Python可能的递归"),
            (r'function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*\1\s*\(', "JS可能的递归"),
        ],
        "large_object_creation": [
            (r'for\s+.*:\s*\n[^}]*new\s+\w+\s*\(', "循环内创建对象"),
            (r'new\s+byte\s*\[\s*\d{7,}\s*\]', "超大数组分配"),
            (r'\.toArray\s*\(\s*\)', "集合转数组（大量数据时OOM风险）"),
            (r'String\s*\+\s*=', "字符串拼接（循环中应使用StringBuilder）"),
        ],
        "lock_issue": [
            (r'synchronized\s*\(\s*this\s*\)', "粗粒度锁（锁this）"),
            (r'synchronized\s*\(\s*\w+\.class\s*\)', "类级别锁（过于宽泛）"),
            (r'\.lock\s*\(\s*\)(?!.*finally)', "加锁但可能未在finally中释放"),
        ],
    }
    
    def __init__(self, project_root: str):
        super().__init__()
        self.project_root = project_root
    
    @property
    def name(self) -> str:
        return "smart_scan"
    
    @property
    def description(self) -> str:
        return """🚀 智能批量代码缺陷扫描工具 - 一次调用完成多项检查

这是 Analysis Agent 的首选工具！在分析开始时优先使用此工具获取项目代码质量概览。

功能：
- 自动识别高风险文件（可能存在运行缺陷的区域）
- 批量检测多种缺陷模式（稳定性、性能、并发、资源泄露）
- 按严重程度汇总结果
- 支持快速模式和完整模式

使用示例:
- 快速全面扫描: {"target": ".", "quick_mode": true}
- 扫描特定目录: {"target": "src/service", "scan_types": ["pattern"]}
- 聚焦特定缺陷: {"target": ".", "focus_defects": ["resource_leak", "loop_db_query"]}

扫描类型:
- pattern: 运行缺陷模式匹配
- all: 所有类型（默认）

输出：按风险级别分类的发现汇总，可直接用于制定进一步分析策略。"""
    
    @property
    def args_schema(self):
        return SmartScanInput
    
    async def _execute(
        self,
        target: str = ".",
        scan_types: Optional[List[str]] = None,
        focus_defects: Optional[List[str]] = None,
        max_files: int = 50,
        quick_mode: bool = False,
        **kwargs
    ) -> ToolResult:
        """执行智能扫描"""
        scan_types = scan_types or ["all"]
        
        # 收集要扫描的文件
        files_to_scan = await self._collect_files(target, max_files, quick_mode)
        
        if not files_to_scan:
            return ToolResult(
                success=True,
                data=f"在目标 '{target}' 中未找到可扫描的文件",
                metadata={"files_scanned": 0}
            )
        
        # 执行扫描
        all_findings = []
        files_with_issues = set()
        
        for file_path in files_to_scan:
            file_findings = await self._scan_file(file_path, focus_defects)
            if file_findings:
                all_findings.extend(file_findings)
                files_with_issues.add(file_path)
        
        # 生成报告
        return self._generate_report(
            files_to_scan, 
            files_with_issues, 
            all_findings,
            quick_mode
        )
    
    async def _collect_files(
        self, 
        target: str, 
        max_files: int, 
        quick_mode: bool
    ) -> List[str]:
        """收集要扫描的文件"""
        full_path = os.path.normpath(os.path.join(self.project_root, target))
        
        # 安全检查
        if not full_path.startswith(os.path.normpath(self.project_root)):
            return []
        
        files = []
        
        # 排除目录
        exclude_dirs = {
            'node_modules', '__pycache__', '.git', 'venv', '.venv',
            'build', 'dist', 'target', '.idea', '.vscode', 'vendor',
            'coverage', '.pytest_cache', '.mypy_cache',
        }
        
        # 支持的代码文件扩展名
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php',
            '.go', '.rb', '.cs', '.c', '.cpp', '.h', '.hpp',
            '.swift', '.m', '.mm', '.kt', '.rs', '.sh', '.bat',
            '.vue', '.html', '.htm', '.xml', '.gradle', '.properties'
        }
        
        # 配置文件扩展名
        config_extensions = {'.json', '.yaml', '.yml', '.env', '.ini', '.cfg', '.plist', '.conf'}
        
        all_extensions = code_extensions | config_extensions
        
        if os.path.isfile(full_path):
            return [os.path.relpath(full_path, self.project_root)]
        
        for root, dirs, filenames in os.walk(full_path):
            # 过滤排除目录
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in all_extensions:
                    continue
                
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, self.project_root)
                
                # 快速模式：只扫描高风险文件
                if quick_mode:
                    is_high_risk = any(
                        re.search(pattern, rel_path, re.IGNORECASE)
                        for pattern in self.HIGH_RISK_PATTERNS
                    )
                    if not is_high_risk:
                        continue
                
                files.append(rel_path)
                
                if len(files) >= max_files:
                    break
            
            if len(files) >= max_files:
                break
        
        return files
    
    async def _scan_file(
        self, 
        file_path: str,
        focus_defects: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """扫描单个文件"""
        full_path = os.path.join(self.project_root, file_path)
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"无法读取文件 {file_path}: {e}")
            return []
        
        lines = content.split('\n')
        findings = []
        
        defect_types = focus_defects or list(self.QUICK_PATTERNS.keys())
        
        for defect_type in defect_types:
            patterns = self.QUICK_PATTERNS.get(defect_type, [])
            
            for pattern, pattern_name in patterns:
                try:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            start = max(0, i - 1)
                            end = min(len(lines), i + 2)
                            context = '\n'.join(lines[start:end])
                            
                            findings.append({
                                "defect_type": defect_type,
                                "pattern_name": pattern_name,
                                "file_path": file_path,
                                "line_number": i + 1,
                                "matched_line": line.strip()[:150],
                                "context": context[:300],
                                "severity": self._get_severity(defect_type),
                            })
                except re.error:
                    continue
        
        return findings
    
    def _get_severity(self, defect_type: str) -> str:
        """获取缺陷严重程度"""
        severity_map = {
            "null_pointer": "high",
            "unhandled_exception": "high",
            "resource_leak": "critical",
            "loop_db_query": "critical",
            "remote_call_in_loop": "critical",
            "unbounded_query": "high",
            "unsafe_collection": "high",
            "unbounded_thread_pool": "critical",
            "infinite_recursion": "critical",
            "large_object_creation": "medium",
            "lock_issue": "high",
        }
        return severity_map.get(defect_type, "medium")
    
    def _generate_report(
        self,
        files_scanned: List[str],
        files_with_issues: set,
        findings: List[Dict],
        quick_mode: bool
    ) -> ToolResult:
        """生成扫描报告"""
        
        # 按严重程度分组
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for f in findings:
            sev = f.get("severity", "medium")
            by_severity[sev].append(f)
        
        # 按缺陷类型分组
        by_type = {}
        for f in findings:
            dtype = f.get("defect_type", "unknown")
            if dtype not in by_type:
                by_type[dtype] = []
            by_type[dtype].append(f)
        
        # 构建报告
        output_parts = [
            f"🔍 智能代码缺陷扫描报告",
            f"{'(快速模式)' if quick_mode else '(完整模式)'}",
            "",
            f"📊 扫描概览:",
            f"- 扫描文件数: {len(files_scanned)}",
            f"- 有问题文件: {len(files_with_issues)}",
            f"- 总发现数: {len(findings)}",
            "",
        ]
        
        # 严重程度统计
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        output_parts.append("📈 按严重程度分布:")
        for sev in ["critical", "high", "medium", "low"]:
            count = len(by_severity[sev])
            if count > 0:
                output_parts.append(f"  {severity_icons[sev]} {sev.upper()}: {count}")
        
        output_parts.append("")
        
        # 缺陷类型统计
        if by_type:
            output_parts.append("📋 按缺陷类型分布:")
            for dtype, dfindings in sorted(by_type.items(), key=lambda x: -len(x[1])):
                output_parts.append(f"  - {dtype}: {len(dfindings)}")
        
        output_parts.append("")
        
        # 详细发现（按严重程度排序，最多显示15个）
        if findings:
            output_parts.append("⚠️ 重点发现 (按严重程度排序):")
            shown = 0
            for sev in ["critical", "high", "medium", "low"]:
                for f in by_severity[sev][:5]:
                    if shown >= 15:
                        break
                    icon = severity_icons[f["severity"]]
                    output_parts.append(f"\n{icon} [{f['severity'].upper()}] {f['defect_type']}")
                    output_parts.append(f"   📍 {f['file_path']}:{f['line_number']}")
                    output_parts.append(f"   🔍 模式: {f['pattern_name']}")
                    output_parts.append(f"   📝 代码: {f['matched_line'][:80]}")
                    shown += 1
                if shown >= 15:
                    break
            
            if len(findings) > 15:
                output_parts.append(f"\n... 还有 {len(findings) - 15} 个发现")
        
        # 建议的下一步
        output_parts.append("")
        output_parts.append("💡 建议的下一步:")
        
        if by_severity["critical"]:
            output_parts.append("  1. ⚠️ 优先处理 CRITICAL 级别缺陷 - 使用 read_file 深入分析")
        if by_severity["high"]:
            output_parts.append("  2. 🔍 分析 HIGH 级别缺陷的上下文和数据流")
        if files_with_issues:
            top_files = list(files_with_issues)[:3]
            output_parts.append(f"  3. 📁 重点审查这些文件: {', '.join(top_files)}")
        
        return ToolResult(
            success=True,
            data="\n".join(output_parts),
            metadata={
                "files_scanned": len(files_scanned),
                "files_with_issues": len(files_with_issues),
                "total_findings": len(findings),
                "by_severity": {k: len(v) for k, v in by_severity.items()},
                "by_type": {k: len(v) for k, v in by_type.items()},
                "findings": findings[:20],
                "high_risk_files": list(files_with_issues)[:10],
            }
        )


class QuickAuditInput(BaseModel):
    """快速审计输入"""
    file_path: str = Field(description="要审计的文件路径")
    deep_analysis: bool = Field(
        default=True,
        description="是否进行深度分析（包括上下文和数据流分析）"
    )


class QuickAuditTool(AgentTool):
    """
    快速文件审计工具
    
    对单个文件进行全面的代码质量审计，包括：
    - 缺陷模式匹配
    - 上下文分析
    - 风险评估
    - 修复建议
    """
    
    def __init__(self, project_root: str):
        super().__init__()
        self.project_root = project_root
    
    @property
    def name(self) -> str:
        return "quick_audit"
    
    @property
    def description(self) -> str:
        return """🎯 快速文件审计工具 - 对单个文件进行全面代码缺陷分析

当 smart_scan 发现高风险文件后，使用此工具进行深入审计。

功能：
- 全面的缺陷模式匹配
- 代码结构分析
- 风险评估和优先级排序
- 具体的修复建议

使用示例:
- {"file_path": "app/service/UserService.java", "deep_analysis": true}

适用场景：
- smart_scan 发现的高风险文件
- 需要详细分析的可疑代码（资源泄露、性能问题等）
- 生成具体的修复建议"""
    
    @property
    def args_schema(self):
        return QuickAuditInput
    
    async def _execute(
        self,
        file_path: str,
        deep_analysis: bool = True,
        **kwargs
    ) -> ToolResult:
        """执行快速审计"""
        full_path = os.path.join(self.project_root, file_path)
        
        # 安全检查
        if not os.path.normpath(full_path).startswith(os.path.normpath(self.project_root)):
            return ToolResult(success=False, error="安全错误：路径越界")
        
        if not os.path.exists(full_path):
            return ToolResult(success=False, error=f"文件不存在: {file_path}")
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return ToolResult(success=False, error=f"读取文件失败: {str(e)}")
        
        lines = content.split('\n')
        
        # 分析结果
        audit_result = {
            "file_path": file_path,
            "total_lines": len(lines),
            "findings": [],
            "code_metrics": {},
            "recommendations": [],
        }
        
        # 代码指标
        audit_result["code_metrics"] = {
            "total_lines": len(lines),
            "non_empty_lines": len([l for l in lines if l.strip()]),
            "comment_lines": len([l for l in lines if l.strip().startswith(('#', '//', '/*', '*'))]),
        }
        
        # 执行模式匹配
        from .pattern_tool import PatternMatchTool
        pattern_tool = PatternMatchTool(self.project_root)
        
        # 使用完整的模式库进行扫描
        for defect_type, config in pattern_tool.PATTERNS.items():
            patterns_dict = config.get("patterns", {})
            
            ext = os.path.splitext(file_path)[1].lower()
            lang_map = {".py": "python", ".js": "javascript", ".ts": "javascript", 
                       ".php": "php", ".java": "java", ".go": "go"}
            language = lang_map.get(ext)
            
            patterns_to_check = patterns_dict.get(language, [])
            patterns_to_check.extend(patterns_dict.get("_common", []))
            
            for pattern, pattern_name in patterns_to_check:
                try:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            start = max(0, i - 2)
                            end = min(len(lines), i + 3)
                            context = '\n'.join(f"{start+j+1}: {lines[start+j]}" for j in range(end-start))
                            
                            finding = {
                                "defect_type": defect_type,
                                "pattern_name": pattern_name,
                                "severity": config.get("severity", "medium"),
                                "line_number": i + 1,
                                "matched_line": line.strip()[:150],
                                "context": context,
                                "description": config.get("description", ""),
                                "cwe_id": config.get("cwe_id", ""),
                            }
                            
                            if deep_analysis:
                                finding["recommendation"] = self._get_recommendation(defect_type)
                            
                            audit_result["findings"].append(finding)
                except re.error:
                    continue
        
        # 生成报告
        return self._format_audit_report(audit_result)
    
    def _get_recommendation(self, defect_type: str) -> str:
        """获取修复建议"""
        recommendations = {
            "null_pointer": "在使用对象前进行空值检查，使用 Optional 或空对象模式避免 NPE。",
            "unhandled_exception": "添加完整的异常处理逻辑，避免空 catch 块，确保资源在异常时正确释放。",
            "resource_leak": "使用 try-with-resources (Java) 或 with 语句 (Python) 确保资源在 finally 中关闭。",
            "loop_db_query": "使用批量查询（IN 子句/JOIN）替代循环内逐条查询，避免 N+1 问题。",
            "remote_call_in_loop": "合并为批量调用，使用异步并行请求减少网络开销。",
            "unbounded_query": "添加 LIMIT 分页参数，限制单次查询数据量，避免 OOM。",
            "unsafe_collection": "使用 ConcurrentHashMap 替代 HashMap，使用 CopyOnWriteArrayList 或同步包装器。",
            "unbounded_thread_pool": "指定 LinkedBlockingQueue 容量上限，配置拒绝策略。使用线程池管理线程。",
            "infinite_recursion": "添加递归终止条件检查，限制递归深度，考虑使用迭代替代递归。",
            "large_object_creation": "在循环外创建对象并复用，使用 StringBuilder 替代字符串拼接。",
            "lock_issue": "缩小锁的作用范围，使用细粒度锁或读写锁，确保在 finally 中释放锁。",
        }
        return recommendations.get(defect_type, "请手动审查此代码段的运行质量。")
    
    def _format_audit_report(self, audit_result: Dict) -> ToolResult:
        """格式化审计报告"""
        findings = audit_result["findings"]
        
        output_parts = [
            f"📋 文件审计报告: {audit_result['file_path']}",
            "",
            f"📊 代码统计:",
            f"  - 总行数: {audit_result['code_metrics']['total_lines']}",
            f"  - 有效代码: {audit_result['code_metrics']['non_empty_lines']}",
            "",
        ]
        
        if not findings:
            output_parts.append("✅ 未发现已知的代码缺陷")
        else:
            # 按严重程度分组
            by_severity = {"critical": [], "high": [], "medium": [], "low": []}
            for f in findings:
                by_severity[f["severity"]].append(f)
            
            severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            
            output_parts.append(f"⚠️ 发现 {len(findings)} 个潜在缺陷:")
            output_parts.append("")
            
            for sev in ["critical", "high", "medium", "low"]:
                for f in by_severity[sev]:
                    icon = severity_icons[sev]
                    output_parts.append(f"{icon} [{sev.upper()}] {f['defect_type']}")
                    output_parts.append(f"   📍 第 {f['line_number']} 行: {f['pattern_name']}")
                    output_parts.append(f"   💻 代码: {f['matched_line'][:80]}")
                    if f.get("cwe_id"):
                        output_parts.append(f"   🔗 CWE: {f['cwe_id']}")
                    if f.get("recommendation"):
                        output_parts.append(f"   💡 建议: {f['recommendation'][:100]}")
                    output_parts.append("")
        
        return ToolResult(
            success=True,
            data="\n".join(output_parts),
            metadata={
                "file_path": audit_result["file_path"],
                "findings_count": len(findings),
                "findings": findings,
                "code_metrics": audit_result["code_metrics"],
            }
        )
