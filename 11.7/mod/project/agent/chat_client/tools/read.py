import base64
import os
import time
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from . import register_tool
from .base import _xml_response


# ============================================================================
# Constants
# ============================================================================
MAX_SIZE_BYTES = 256 * 1024  # 256 KB - file size limit
MAX_TOKENS = 25000           # Token limit for output
MAX_LINES_TO_READ = 2000     # Default lines to read
FAST_PATH_THRESHOLD = 10 * 1024 * 1024  # 10 MB - fast path threshold
MAX_LINE_LENGTH = 2000       # Max characters per line

# Device file blacklist (would block or produce infinite output)
DEVICE_FILE_BLACKLIST = {
    '/dev/zero', '/dev/random', '/dev/urandom', '/dev/full',
    '/dev/stdin', '/dev/tty', '/dev/console',
    '/dev/stdout', '/dev/stderr',
}

# Binary file extensions (cannot read as text)
BINARY_EXTENSIONS = {
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.exe', '.dll', '.so', '.o', '.a', '.bin',
    '.class', '.jar', '.war', '.pyc', '.pyo',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.tiff', '.webp', '.svg',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.flv',
    '.woff', '.woff2', '.eot', '.ttf',
    '.db', '.sqlite', '.sqlite3',
}

# Image/PDF extensions (can return as attachments)
ATTACHMENT_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.pdf',
}

# MIME types for attachments
MIME_TYPE_MAP = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.bmp': 'image/bmp',
    '.ico': 'image/x-icon',
    '.pdf': 'application/pdf',
}


# ============================================================================
# File State Cache for Deduplication
# ============================================================================
@dataclass
class FileState:
    """Cache entry for file state to avoid redundant reads."""
    file_path: str
    total_lines: int
    mtime: float
    last_read_start: int
    last_read_end: int


# ============================================================================
# Custom Exceptions
# ============================================================================
class FileTooLargeError(Exception):
    """Raised when file exceeds MAX_SIZE_BYTES."""
    pass


class MaxFileReadTokenExceededError(Exception):
    """Raised when content exceeds MAX_TOKENS."""
    pass


# ============================================================================
# ReadTool Class
# ============================================================================
class ReadTool:
    """
    File reader with comprehensive type detection, size/token limits,
    and optimized read paths.
    """

    def __init__(
        self,
        file_path: str,
        offset: int = 1,
        limit: int = MAX_LINES_TO_READ,
    ):
        self.file_path = file_path
        self.offset = max(1, offset)
        self.limit = max(1, limit)
        self._ext = os.path.splitext(file_path)[1].lower()

    def execute(self) -> str:
        """
        Execute the read operation and return formatted result.
        Returns XML-formatted string via _xml_response.
        """
        try:
            # 1. Path validation and expansion
            self._validate_path()

            # 2. Check if path is a directory
            if os.path.isdir(self.file_path):
                # return self._read_directory(session_id)
                raise ValueError(f"Path is a directory: {self.file_path}. Please provide a file path.")

            # 3. Device file check
            self._check_device_file()

            # 4. Binary file check
            if self._is_binary_extension():
                # return self._handle_binary_file(session_id)
                raise ValueError(f"File appears to be a binary {self._ext} file. Please provide a text file path.")

            # 5. Get file metadata BEFORE reading
            file_stat = os.stat(self.file_path)
            file_size = file_stat.st_size
            file_mtime = file_stat.st_mtime

            # 6. File size limit check (256KB) - FAIL FAST before reading
            if file_size > MAX_SIZE_BYTES:
                return _xml_response(
                    "Read",
                    "error",
                    f"File content ({self._format_size(file_size)}) exceeds maximum allowed size (256KB). "
                    f"Use offset and limit parameters to read smaller sections."
                )

            # 7. Fast path for small files, streaming for large
            if file_size < FAST_PATH_THRESHOLD:
                content, total_lines, start_line, end_line = self._fast_path_read()
            else:
                content, total_lines, start_line, end_line = self._streaming_path_read()

            # 9. Token validation (approximate)
            approx_tokens = len(content) // 4
            if approx_tokens > MAX_TOKENS:
                return _xml_response(
                    "Read",
                    "error",
                    f"File content (approx {approx_tokens} tokens) exceeds maximum allowed tokens (25000). "
                    f"Use offset and limit parameters to read smaller sections."
                )

            # 10. Format output with line numbers
            formatted_content = self._format_content(content, start_line, end_line, total_lines)

            # 12. Return response - NEVER truncated (Read tool完整性原则)
            return _xml_response("Read", "done", formatted_content, max_chars=0)

        except FileNotFoundError as e:
            return _xml_response("Read", "error", str(e))
        except PermissionError as e:
            return _xml_response("Read", "error", f"Permission denied: {str(e)}")
        except Exception as e:
            return _xml_response("Read", "error", f"Read failed: {str(e)}")

    def _validate_path(self):
        """Validate path is absolute and exists."""
        if not os.path.isabs(self.file_path):
            raise ValueError(
                f"File path must be absolute: {self.file_path}. "
                f"Please provide an absolute path."
            )
        if not os.path.exists(self.file_path):
            # Try to suggest similar files
            parent_dir = os.path.dirname(self.file_path)
            filename = os.path.basename(self.file_path)
            if os.path.exists(parent_dir):
                try:
                    candidates = os.listdir(parent_dir)
                    # Simple similarity check
                    similar = [
                        c for c in candidates
                        if filename.lower() in c.lower() or c.lower() in filename.lower()
                    ]
                    if similar:
                        raise FileNotFoundError(
                            f"File not found: {self.file_path}. "
                            f"Did you mean: {', '.join(similar[:3])}?"
                        )
                except:
                    pass
            raise FileNotFoundError(f"File not found: {self.file_path}")

    def _check_device_file(self):
        """Check if path is a device file that would block."""
        normalized = os.path.normpath(self.file_path)
        for device in DEVICE_FILE_BLACKLIST:
            if normalized.startswith(device):
                raise ValueError(
                    f"Cannot read '{self.file_path}': this device file would block "
                    f"or produce infinite output."
                )

    def _is_binary_extension(self) -> bool:
        """Check if file has a binary extension."""
        return self._ext in BINARY_EXTENSIONS

    def _handle_binary_file(self) -> str:
        """Handle binary file detection."""
        return _xml_response(
            "Read",
            "done",
            f"<path>{self.file_path}</path>\n<type>binary</type>\n<content>"
            f"This tool cannot read binary files. "
            f"The file appears to be a binary {self._ext} file. "
            f"Please use appropriate tools for binary file analysis.</content>",
            max_chars=0
        )

    def _handle_attachment_file(self) -> str:
        """Handle image/PDF files and return as base64 attachment."""
        mime_type = MIME_TYPE_MAP.get(self._ext, 'application/octet-stream')
        
        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            
            if file_size > MAX_SIZE_BYTES:
                return _xml_response(
                    "Read",
                    "error",
                    f"File content ({self._format_size(file_size)}) exceeds maximum allowed size (256KB). "
                    f"This file is too large to read as attachment."
                )
            
            base64_data = base64.b64encode(file_data).decode('ascii')
            
            return _xml_response(
                "Read",
                "done",
                f"<path>{self.file_path}</path>\n<type>attachment</type>\n<mimeType>{mime_type}</mimeType>\n<size>{file_size}</size>\n<data>\n{base64_data}\n</data>",
                max_chars=0
            )
        except Exception as e:
            return _xml_response(
                "Read",
                "error",
                f"Failed to read attachment: {str(e)}"
            )

    def _read_directory(self) -> str:
        """Read and format directory listing."""
        try:
            entries = os.listdir(self.file_path)
        except PermissionError:
            return _xml_response(
                "Read",
                "error",
                f"Permission denied: {self.file_path}"
            )

        entries.sort()
        total_entries = len(entries)

        start = self.offset - 1
        end = start + self.limit
        sliced = entries[start:end]
        truncated = end < total_entries

        entry_lines = []
        for entry in sliced:
            full_p = os.path.join(self.file_path, entry)
            if os.path.isdir(full_p):
                entry_lines.append(entry + "/")
            else:
                entry_lines.append(entry)

        output = f"<path>{self.file_path}</path>\n<type>directory</type>\n<entries>\n"
        output += "\n".join(entry_lines)
        if truncated:
            output += (
                f"\n(Showing {len(sliced)} of {total_entries} entries. "
                f"Use offset={self.offset + len(sliced)} to continue.)"
            )
        else:
            output += f"\n({total_entries} entries)"
        output += "\n</entries>"

        return _xml_response("Read", "done", output, max_chars=0)

    def _fast_path_read(self) -> Tuple[str, int, int, int]:
        """
        Read entire file at once (for files < 10MB).
        Returns: (content, total_lines, start_line, end_line)
        """
        with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
            all_lines = f.readlines()

        total_lines = len(all_lines)
        start_index = self.offset - 1
        end_index = min(total_lines, start_index + self.limit)

        selected_lines = all_lines[start_index:end_index]
        content = "".join(selected_lines)

        return content, total_lines, self.offset, min(end_index, total_lines)

    def _streaming_path_read(self) -> Tuple[str, int, int, int]:
        """
        Read file using stream, keeping only requested lines (for files >= 10MB).
        Returns: (content, total_lines, start_line, end_line)
        """
        start_line = self.offset
        end_line = self.offset + self.limit - 1

        content_lines = []
        total_lines = 0
        current_line = 0

        with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                current_line += 1
                total_lines = current_line

                if current_line < start_line:
                    continue
                if current_line > end_line:
                    break

                # Truncate long lines
                if len(line) > MAX_LINE_LENGTH:
                    line = line[:MAX_LINE_LENGTH] + "...\n"

                content_lines.append(line)

        content = "".join(content_lines)
        actual_end = min(end_line, total_lines)

        return content, total_lines, start_line, actual_end

    def _format_content(
        self,
        content: str,
        start_line: int,
        end_line: int,
        total_lines: int,
    ) -> str:
        """Format content with line numbers and navigation hints."""
        lines = content.split('\n')
        # Remove trailing empty line if file ends with newline
        if lines and lines[-1] == '':
            lines = lines[:-1]

        numbered_lines = []
        for i, line in enumerate(lines):
            line_num = start_line + i
            numbered_lines.append(f"{line_num}: {line}")

        output = f"<path>{self.file_path}</path>\n<type>file</type>\n<content>\n"
        output += "\n".join(numbered_lines)

        if end_line < total_lines:
            output += (
                f"\n\n(Showing lines {start_line}-{end_line} of {total_lines}. "
                f"Use offset={end_line + 1} to continue.)"
            )
        else:
            output += f"\n\n(End of file - total {total_lines} lines)"

        output += "\n</content>"
        return output

    @staticmethod
    def _format_size(byte_size: int) -> str:
        """Format bytes to human-readable size."""
        if byte_size < 1024:
            return f"{byte_size}B"
        elif byte_size < 1024 * 1024:
            return f"{byte_size / 1024:.1f}KB"
        else:
            return f"{byte_size / (1024 * 1024):.1f}MB"

@register_tool(category="Agent", name_cn="读取文件", risk_level="medium")
def Read(file_path: str, offset: int = 1, limit: int = 2000, **kwargs) -> str:
    """
    Read a file or directory from the local filesystem. If the path does not exist, an error is returned.
    
    Usage:
    - The filePath parameter should be an absolute path.
    - By default, this tool returns up to 2000 lines from the start of the file.
    - The offset parameter is the line number to start from (1-indexed).
    - To read later sections, call this tool again with a larger offset.
    - Use the grep tool to find specific content in large files or files with long lines.
    - If you are unsure of the correct file path, use the glob tool to look up filenames by glob pattern.
    - Contents are returned with each line prefixed by its line number as `<line>: <content>`. For example, if a file has contents "foo\\n", you will receive "1: foo\\n". For directories, entries are returned one per line (without line numbers) with a trailing `/` for subdirectories.
    - Any line longer than 2000 characters is truncated.
    - Call this tool in parallel when you know there are multiple files you want to read.
    - Avoid tiny repeated slices (30 line chunks). If you need more context, read a larger window.
    - This tool can read image files and PDFs and return them as file attachments.
    
    Args:
        file_path: The absolute path to the file to read.
        offset: The line number to start reading from (must be at least 1). Only provide if the file is too large to read at once.
        limit: The number of lines to read (must be at least 1, cannot be negative). Only provide if the file is too large to read at once.
    """
    tool = ReadTool(file_path=file_path, offset=offset, limit=limit)
    return tool.execute()