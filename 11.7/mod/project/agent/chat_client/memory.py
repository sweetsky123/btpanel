import json
import os
import time
import uuid
from typing import List, Dict, Any, Union

class MemoryManager:
    def __init__(self, session_id: str, sessions_dir: str = "sessions", sliding_window_size: int = 10, skill_agent_id: str = None, model_name: str = None):
        self.session_id = session_id
        self.sliding_window_size = sliding_window_size
        self.skill_agent_id = skill_agent_id
        self.model_name = model_name

        self.session_dir = os.path.join(sessions_dir, session_id)
        self.file_path = os.path.join(self.session_dir, "sessions.json")
        self.meta_file_path = os.path.join(self.session_dir, "meta.json")
        self.history: List[Dict[str, Any]] = []
        self._ensure_sessions_dir()
        self.load_session()
        self._load_or_create_meta()

    def _ensure_sessions_dir(self):
        if not os.path.exists(self.session_dir):
            os.makedirs(self.session_dir)

    def _load_or_create_meta(self):
        if not os.path.exists(self.meta_file_path):
            meta = {
                "session_id": self.session_id,
                "skill_agent_id": self.skill_agent_id,
                "model_name": self.model_name,
                "created_at": time.time(),
                "total_tokens": 0,
                "input_tokens": 0,
                "output_tokens": 0
            }
            if self.skill_agent_id:
                meta["skill_agent_id"] = self.skill_agent_id
            try:
                with open(self.meta_file_path, 'w', encoding='utf-8') as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
            except:
                pass
        else:
            try:
                with open(self.meta_file_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                
                needs_save = False
                if self.skill_agent_id and not meta.get("skill_agent_id"):
                    meta["skill_agent_id"] = self.skill_agent_id
                    needs_save = True
                
                if self.model_name and meta.get("model_name") != self.model_name:
                    meta["model_name"] = self.model_name
                    needs_save = True
                    
                if "total_tokens" not in meta:
                    meta["total_tokens"] = 0
                    meta["input_tokens"] = 0
                    meta["output_tokens"] = 0
                    needs_save = True
                    
                if needs_save:
                    with open(self.meta_file_path, 'w', encoding='utf-8') as f:
                        json.dump(meta, f, ensure_ascii=False, indent=2)
            except:
                pass

    def update_meta_tokens(self, total_tokens: int, input_tokens: int, output_tokens: int):
        try:
            if os.path.exists(self.meta_file_path):
                with open(self.meta_file_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
            else:
                meta = {
                    "session_id": self.session_id,
                    "skill_agent_id": self.skill_agent_id,
                    "created_at": time.time()
                }
            
            meta["total_tokens"] = total_tokens
            meta["input_tokens"] = input_tokens
            meta["output_tokens"] = output_tokens
            meta["updated_at"] = time.time()
            
            with open(self.meta_file_path, 'w', encoding='utf-8') as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)
        except:
            pass

    def load_session(self):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    self.history = json.load(f)
            except Exception as e:
                self.history = []
        else:
            self.history = []

    def save_session(self):
        try:
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            pass

    def add_message(self, role: str, content: Union[str, List[Dict[str, Any]]], id: str = None, **kwargs):
        msg = {
            "id": id if id else str(uuid.uuid4()),
            "role": role,
            "content": content,
            "timestamp": time.time(),
            **kwargs
        }
        self.history.append(msg)
        self.save_session()
        return msg
    
    def _split_into_rounds(self) -> List[List[Dict[str, Any]]]:
        """
        将历史消息分割为对话轮次。
        一轮对话定义为：从一个 'user' 消息开始，包含随后的所有 'assistant'/'tool' 消息，
        直到遇到下一个 'user' 消息或历史结束。
        """
        rounds = []
        current_round = []
        
        for msg in self.history:
            # 过滤掉 reasoning_content
            clean_msg = msg.copy()
            # if "reasoning_content" in clean_msg:
                # del clean_msg["reasoning_content"]

            if clean_msg['role'] == 'user':
                if current_round:
                    rounds.append(current_round)
                current_round = [clean_msg]
            else:
                # 兼容性：如果历史记录不是以 user 开头（罕见），也归入当前轮次（或创建新轮次）
                if not current_round and not rounds:
                    # 孤立的非 user 消息，作为第一轮
                    current_round = [clean_msg]
                else:
                    current_round.append(clean_msg)
        
        if current_round:
            rounds.append(current_round)
        
        return rounds
    
    def get_sliding_window(self) -> List[Dict[str, Any]]:
        """
        返回最后 N 轮对话中的所有消息。
        配置项 SLIDING_WINDOW_SIZE 现在表示轮次数，而非单条消息数。
        """
        rounds = self._split_into_rounds()
        
        # 获取最后 N 轮
        last_n_rounds = rounds[-self.sliding_window_size:]
        
        # 展平为消息列表
        window_messages = []
        for r in last_n_rounds:
            window_messages.extend(r)
        
        return window_messages

    def get_full_history(self) -> List[Dict[str, Any]]:
        return self.history

    def get_total_rounds(self) -> int:
        return len(self._split_into_rounds())

    def get_message_rounds(self) -> int:
        """
        获取当前对话轮数
        Returns:
            int: 对话轮次数量
        """
        return len(self._split_into_rounds())

    def estimate_total_tokens(self) -> int:
        """
        估算当前消息总 token 数
        使用启发式算法：统计所有文本和工具调用的字符数，乘以 0.3 系数
        适用于 qwen 模型的近似估算
        Returns:
            int: 估算的 token 总数
        """
        total_chars = 0
        for msg in self.history:
            content = msg.get('content', '')
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                # 处理多模态内容（文本类型）
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        total_chars += len(item.get('text', ''))
                    elif isinstance(item, str):
                        total_chars += len(item)
            # 估算 tool_calls 的 token
            if 'tool_calls' in msg:
                for tc in msg['tool_calls']:
                    func = tc.get('function', {})
                    total_chars += len(func.get('name', ''))
                    total_chars += len(func.get('arguments', ''))
        return int(total_chars * 0.3)

    def compact_messages(self, summary_msg: Dict, messages_to_keep: List) -> None:
        """
        执行消息压缩，将历史替换为摘要消息+保留的最近消息
        压缩后结构：[summary_msg, ...messages_to_keep]
        Args:
            summary_msg: 压缩摘要消息字典，role为user，包含历史摘要
            messages_to_keep: 需要保留的最近消息列表（最后N轮对话）
        """
        self.history = [summary_msg] + messages_to_keep
        self.save_session()

    def check_auto_compact(self, max_context_tokens: int, threshold_ratio: float = 0.75) -> bool:
        """
        检查是否需要自动压缩（预留方法，当前不启用）
        Args:
            max_context_tokens: 最大上下文token数
            threshold_ratio: 触发压缩的阈值比例（已使用token / 最大token）
        Returns:
            bool: 是否需要压缩
        Note: 此方法当前仅作为预留入口，自动压缩功能未启用
        """
        # 自动压缩功能当前未启用，此方法仅作为预留代码位置
        # TODO: 实现自动压缩检查逻辑
        # 1. 估算当前token使用量: estimated = self.estimate_total_tokens()
        # 2. 计算使用比例: ratio = estimated / max_context_tokens
        # 3. 如果 ratio >= threshold_ratio，返回 True
        # 4. 考虑电路断路器：连续失败次数超过上限则暂停自动压缩
        return False
