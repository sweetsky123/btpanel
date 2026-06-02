"""
工具返回体系基础模块。

提供统一的 XML 响应格式、内容长度治理、外部存储等核心功能。
参照 CONTEXT_MANAGEMENT_DESIGN.md 中的上下文管理设计模式实现。
"""

import os
import time
import tempfile
from typing import Optional, Tuple


# ============================================================================
# 常量定义
# ============================================================================
OTHER_MAX_RETURN_CHARS = 50000  # 大多数工具的字符限制
# 截断预览配置
HEAD_BYTES = 3000   # 头部保留字节数
TAIL_BYTES = 1000   # 尾部保留字节数

# 预览大小（字节）
PREVIEW_SIZE_BYTES = HEAD_BYTES + TAIL_BYTES  # 3000 + 1000 = 4000 字节


def _format_file_size(byte_size: int) -> str:
    """
    将字节大小转换为人类可读的字符串格式（KB、MB、GB）。

    参数:
        byte_size: 字节数。

    返回:
        格式化后的大小字符串，如 '12.5KB'、'3.2MB' 等。
    """
    if byte_size < 1024:
        return f"{byte_size}B"
    elif byte_size < 1024 * 1024:
        return f"{byte_size / 1024:.1f}KB"
    elif byte_size < 1024 * 1024 * 1024:
        return f"{byte_size / (1024 * 1024):.1f}MB"
    else:
        return f"{byte_size / (1024 * 1024 * 1024):.1f}GB"


# ============================================================================
# 辅助函数
# ============================================================================

def calculate_utf8_size(content: str) -> int:
    """
    计算字符串的 UTF-8 编码字节大小。

    参数:
        content: 要测量的字符串。

    返回:
        字符串 UTF-8 编码后的字节数。
    """
    return len(content.encode("utf-8"))


def build_truncated_preview(
    content: str,
    max_chars: int = OTHER_MAX_RETURN_CHARS,
    head_bytes: int = HEAD_BYTES,
    tail_bytes: int = TAIL_BYTES,
) -> Tuple[str, int]:
    """
    构建带有字符数限制和头尾字节保留的截断预览。

    当内容超过 max_chars（字符数）时，返回包含头部 head_bytes 和尾部 tail_bytes 的预览，
    中间以截断占位符填充。

    参数:
        content: 原始内容字符串。
        max_chars: 允许的最大字符数（默认 50K，适用于大多数工具）。
        head_bytes: 从开头保留的字节数。
        tail_bytes: 从结尾保留的字节数。

    返回:
        一个元组 (preview_string, total_chars):
        - preview_string: 截断后的预览内容，包含占位符。
        - total_chars: 原始内容的字符总数。
    """
    total_chars = len(content)

    # 如果内容在字符限制内，直接返回
    if total_chars <= max_chars:
        return content, total_chars

    # 编码为字节以进行精确的字节级切片
    encoded = content.encode("utf-8")
    total_bytes = len(encoded)

    # 提取头部内容（处理 UTF-8 多字节字符边界）
    head_end = head_bytes
    # 如果处于多字节字符中间，向前调整
    while head_end < len(encoded) and (encoded[head_end] & 0xC0) == 0x80:
        head_end -= 1
    head_part = encoded[:head_end].decode("utf-8", errors="ignore")

    # 提取尾部内容（处理 UTF-8 多字节字符边界）
    tail_start = len(encoded) - tail_bytes
    # 如果处于多字节字符中间，向后调整
    while tail_start > 0 and (encoded[tail_start] & 0xC0) == 0x80:
        tail_start += 1
    tail_part = encoded[tail_start:].decode("utf-8", errors="ignore")

    # 构建包含总字符数的占位符
    placeholder = "\n...[Truncated, total {total} characters]...\n".format(total=total_chars)

    # 组装预览
    preview = f"{head_part}{placeholder}{tail_part}"
    return preview, total_chars


def safe_write_atomic(file_path: str, content: str) -> bool:
    """
    使用临时文件 + 重命名的方式原子化写入文件内容。

    这确保文件要么完全写入，要么不存在，
    避免部分写入导致数据损坏。

    参数:
        file_path: 目标文件路径。
        content: 要写入的内容。

    返回:
        如果写入成功返回 True，否则返回 False。
    """
    dir_path = os.path.dirname(file_path)

    # 确保目录存在
    try:
        os.makedirs(dir_path, exist_ok=True)
    except OSError:
        return False

    # 先写入临时文件，然后重命名以实现原子性
    temp_path = file_path + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())  # 确保数据已刷新到磁盘

        # 原子化重命名（在 Windows 上需要先删除已存在的文件）
        if os.path.exists(file_path):
            os.replace(temp_path, file_path)
        else:
            os.rename(temp_path, file_path)

        return True
    except OSError:
        # 失败时清理临时文件
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass
        return False


def persist_tool_result(
    tool_name: str,
    content: str,
) -> Optional[str]:
    """
    将完整的工具结果持久化到外部文件。

    文件存储路径: /tmp/bt_agent_tmp/tool_result/{tool_name}_{timestamp}.txt

    参数:
        tool_name: 产生结果的工具名称。
        content: 要持久化的完整内容。

    返回:
        如果持久化成功，返回文件路径；否则返回 None。
    """
    # 使用固定存储路径
    storage_dir = "/tmp/bt_agent_tmp/tool_result"
    timestamp = int(time.time() * 1000)  # 毫秒精度
    filename = f"{tool_name}_{timestamp}.txt"
    file_path = os.path.join(storage_dir, filename)

    if safe_write_atomic(file_path, content):
        return file_path

    return None


def process_tool_return(
    tool_name: str,
    content: str,
    max_chars: int = OTHER_MAX_RETURN_CHARS,
) -> str:
    """
    处理工具返回内容，执行长度治理。

    检查内容是否超过 max_chars。如果超过：
    1. 生成截断预览（头部 + 尾部字节）。
    2. 将完整内容持久化到外部存储。
    3. 追加关于外部存储的通知。

    参数:
        tool_name: 工具名称。
        content: 原始工具输出。
        max_chars: 允许的最大字符数（默认 50K，BashTool 使用 30K）。

    返回:
        处理后的内容（原始内容或带通知的截断内容）。
    """
    content_chars = len(content)

    # max_chars <= 0 表示不限制（永不截断）
    if max_chars <= 0:
        return content

    # 检查内容是否超过字符限制
    if content_chars <= max_chars:
        return content

    # 使用工具的特定限制生成截断预览
    preview, total_chars = build_truncated_preview(content, max_chars=max_chars)

    # 计算原始内容的字节大小
    original_size_bytes = calculate_utf8_size(content)

    # 将完整内容持久化到外部存储
    file_path = persist_tool_result(tool_name, content)

    # 构建最终预览和通知（类似 CONTEXT_MANAGEMENT_DESIGN.md 格式）
    if file_path:
        notice = (
            f"\n\nOutput too large ({_format_file_size(original_size_bytes)}). "
            f"Full output saved to: {file_path}\n\n"
            f"Preview (first {_format_file_size(PREVIEW_SIZE_BYTES)}):\n"
            f"{preview}"
        )
    else:
        # 如果持久化失败，仍显示截断消息
        notice = (
            f"\n\nOutput too large ({_format_file_size(original_size_bytes)}). "
            f"Full output could not be saved to external storage.\n\n"
            f"Preview (first {_format_file_size(PREVIEW_SIZE_BYTES)}):\n"
            f"{preview}"
        )

    return notice


# ============================================================================
# XML 响应生成
# ============================================================================

def _xml_response(
    tool_name: str,
    status: str,
    content: str,
    max_chars: int = OTHER_MAX_RETURN_CHARS,
) -> str:
    """
    生成标准化的工具执行 XML 响应。

    所有工具必须使用此函数返回结果。响应包含：
    - tool_name: 执行工具的名称。
    - status: 执行状态（如 'done'、'error'、'running'）。
    - content: 工具输出内容（自动进行长度治理处理）。

    参数:
        tool_name: 工具名称（必填）。
        status: 执行状态字符串。
        content: 工具输出内容。
        max_chars: 允许的最大字符数（默认 50K，BashTool 使用 30K）。

    返回:
        格式化的 XML 响应字符串。
    """
    # 处理内容长度治理
    processed_content = process_tool_return(
        tool_name=tool_name,
        content=content,
        max_chars=max_chars,
    )

    # 构建包含显式工具名的 XML 响应
    return (
        f"\n<tool>"
        f"\n<tool_name>{tool_name}</tool_name>"
        f"\n<toolcall_status>{status}</toolcall_status>"
        f"\n<toolcall_result>"
        f"\n{processed_content}"
        f"\n</toolcall_result>"
        f"\n</tool>\n"
    )
