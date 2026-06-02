# coding: utf-8
import json
import uuid
import time
import os
import re
import logging
import datetime
import public

class ContextCompactor:
    """
    上下文压缩器 - 封装完整的会话压缩流程
    压缩后消息结构：[边界标记] + [压缩摘要] + [保留的最近N轮消息]
    """
    def __init__(self, api_key, base_url, default_headers=None, config=None):
        """
        初始化压缩器
        Args:
            api_key: OpenAI API 密钥
            base_url: OpenAI API 基础地址
            default_headers: 默认请求头字典（可选）
            config: 配置字典（可选），包含以下字段：
                - model_name (str): 用于生成摘要的模型名称，默认 qwen3.5-plus
                - temperature (float): 温度参数，默认 0.3
                - max_tokens (int): 摘要最大输出token数，默认 4096
                - preserve_rounds (int): 压缩后保留的最近对话轮数，默认 3
                - system_prompt (str): 自定义压缩系统提示词，为空则从模板文件加载
        """
        import openai
        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            default_headers=default_headers or {}
        )
        self.model_name = config.get("model_name", "qwen3.5-plus") if config else "qwen3.5-plus"
        self.temperature = float(config.get("temperature", 0.3)) if config else 0.3
        self.max_tokens = int(config.get("max_tokens", 4096)) if config else 4096
        self.preserve_rounds = int(config.get("preserve_rounds", 3)) if config else 3
        self.system_prompt = config.get("system_prompt", "") if config else ""

    def compact_session(self, session_id, sessions_dir, preserve_rounds=None):
        """
        完整压缩流程：读取会话 -> 生成摘要 -> 压缩保存 -> 记录日志
        外部调用只需传入 session_id、sessions_dir 和必要的 API 参数
        Args:
            session_id (str): 会话ID
            sessions_dir (str): 会话目录路径（绝对路径）
            preserve_rounds (int, optional): 覆盖默认保留轮数
        Returns:
            dict: 压缩结果，包含以下字段：
                - success (bool): 是否成功
                - data (dict): 成功时的压缩详情（summary、token对比等）
                - error (str): 失败时的错误信息
        """
        session_file = os.path.join(sessions_dir, session_id, 'sessions.json')
        session_dir_path = os.path.join(sessions_dir, session_id)

        # 检查会话文件是否存在
        if not os.path.exists(session_file):
            return {"success": False, "error": "会话不存在"}

        # 读取会话历史
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except:
            return {"success": False, "error": "读取会话记录失败"}

        # 获取对话轮数和token估算
        message_rounds = self.get_message_rounds(history)

        pre_tokens = self._calculate_tokens(history)

        # 确定保留轮数
        rounds_to_keep = preserve_rounds if preserve_rounds and preserve_rounds > 0 else self.preserve_rounds

        # 生成压缩日志路径并记录开始信息
        compact_log_path = self._get_log_path(session_dir_path)
        compact_start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        self._write_log(compact_log_path, [
            "=" * 60,
            "压缩操作开始 - " + compact_start_time,
            "=" * 60, "",
            "--- 会话信息 ---",
            "Session ID: " + str(session_id),
            "对话轮数: " + str(message_rounds), "",
            "--- 压缩参数 ---",
            "模型名称: " + str(self.model_name),
            "Temperature: " + str(self.temperature),
            "Max Tokens: " + str(self.max_tokens),
            "保留轮数: " + str(rounds_to_keep), "",
            "--- 压缩前状态 ---",
            "消息总数: " + str(len(history)),
            "估算 Token 数: " + str(pre_tokens), "",
        ])

        try:
            # 记录压缩前原始消息预览    
            self._write_log(compact_log_path, [ 
                "--- 压缩前原始消息 (前500字符预览) ---",       
                json.dumps(history, ensure_ascii=False), "",    
            ])

            # 记录系统提示词预览
            if self.system_prompt:
                self._write_log(compact_log_path, [
                    "--- 压缩系统提示词 (前500字符预览) ---",
                    self.system_prompt, "",
                ])

            # 执行压缩核心逻辑
            compacted_messages, summary, _, post_tokens = self.compact(history)

            if compacted_messages is None:
                self._write_log(compact_log_path, ["--- 压缩失败 ---", "原因: 消息过少", ""])
                return {"success": False, "error": "压缩失败：消息过少"}

            # 直接使用 compact 返回的完整消息结构
            self._save_session(session_file, compacted_messages)

            # 计算保留的消息数量（compacted_messages[0]是摘要，其余是保留消息）
            messages_to_keep_count = len(compacted_messages) - 1

            # 更新 meta.json 中的 token 信息
            self._update_meta_tokens(session_dir_path)

            # 计算压缩效果
            token_reduction = round((1 - post_tokens / pre_tokens) * 100, 1) if pre_tokens > 0 else 0
            compact_end_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # 记录压缩结果
            self._write_log(compact_log_path, [
                "--- 压缩生成摘要 (前500字符预览) ---",
                summary, "",
                "--- 压缩后状态 ---",
                "保留消息数: " + str(messages_to_keep_count),
                "压缩后消息结构: [边界标记] + [摘要消息] + [" + str(messages_to_keep_count) + " 条保留消息]",
                "压缩后估算 Token 数: " + str(post_tokens),
                "Token 减少: " + str(token_reduction) + "%", "",
                "--- 压缩后消息结构 ---",
                "消息总数: " + str(len(compacted_messages)),
                "  - 摘要消息(边界标记): role=" + str(compacted_messages[0].get('role', 'N/A')) + ", is_compact_summary=" + str(compacted_messages[0].get('is_compact_summary', False)),
                "  - 保留消息: " + str(messages_to_keep_count) + " 条", "",
                "  - 压缩后消息: " + json.dumps(compacted_messages, ensure_ascii=False), "",
                "=" * 60,
                "压缩操作完成 - " + compact_end_time,
                "=" * 60, "",
            ])

            return {
                "success": True,
                "data": {
                    "summary": summary,
                    "pre_compact_tokens": pre_tokens,
                    "post_compact_tokens": post_tokens,
                    "preserved_rounds": rounds_to_keep,
                    "message_rounds_before": message_rounds,
                    "message_rounds_after": messages_to_keep_count + 1,
                    "token_reduction": token_reduction,
                    "compacted_at": compact_end_time,
                    "log_file": os.path.basename(compact_log_path)
                }
            }
        except Exception as e:
            self._write_log(compact_log_path, [
                "--- 压缩失败: 未知错误 ---",
                "错误类型: " + type(e).__name__,
                "错误信息: " + str(e),
                "失败时间: " + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "",
            ])
            return {"success": False, "error": "压缩失败：" + str(e)}

    def compact(self, messages):
        """
        压缩核心逻辑：将消息列表压缩为 [摘要 + 保留消息]
        Args:
            messages: 完整的消息历史列表（OpenAI格式）
        Returns:
            (compacted_messages, summary, pre_tokens, post_tokens)
            如果消息过少则返回 (None, None, 0, 0)
        """

        pre_tokens = self._calculate_tokens(messages)
        rounds = self._split_into_rounds(messages)

        # 分割需要摘要的消息和保留的消息
        if len(rounds) <= self.preserve_rounds:
            messages_to_summarize = messages
            messages_to_keep = []
        else:
            messages_to_summarize = []
            messages_to_keep = []
            for r in rounds[:-self.preserve_rounds]:
                messages_to_summarize.extend(r)
            for r in rounds[-self.preserve_rounds:]:
                messages_to_keep.extend(r)

        # 清理需要摘要的消息中的 image_url base64 内容,避免上下文过大
        messages_to_summarize = self._clean_image_base64(messages_to_summarize)

        # 调用AI生成摘要
        summary = self._generate_summary(messages_to_summarize)
        if not summary:
            raise Exception("Failed to generate conversation summary")

        # 构建压缩后的消息结构
        summary_msg = self._build_compacted_messages(summary)
        
        compacted_messages = [summary_msg] + messages_to_keep
        post_tokens = self._calculate_tokens(compacted_messages)

        return compacted_messages, summary, pre_tokens, post_tokens

    def _get_messages_to_keep(self, history):
        """
        从历史消息中提取需要保留的最近N轮消息
        Args:
            history: 完整消息历史
        Returns:
            需要保留的消息列表
        """
        rounds = self._split_into_rounds(history)
        if len(rounds) > self.preserve_rounds:
            messages_to_keep = []
            for r in rounds[-self.preserve_rounds:]:
                messages_to_keep.extend(r)
            return messages_to_keep
        return history

    def _save_session(self, session_file, history):
        """
        保存会话消息到文件
        Args:
            session_file: sessions.json 文件路径
            history: 消息历史列表
        """
        try:
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
        except:
            pass

    def _update_meta_tokens(self, session_dir_path):
        """
        更新 meta.json 中的 token 信息
        重新读取 sessions.json 并计算完整消息的 token 数，确保准确性
        Args:
            session_dir_path: 会话目录路径
        """
        meta_file_path = os.path.join(session_dir_path, 'meta.json')
        session_file_path = os.path.join(session_dir_path, 'sessions.json')
        
        try:
            # 读取压缩后的 sessions.json 重新计算 token
            if not os.path.exists(session_file_path):
                return
            
            with open(session_file_path, 'r', encoding='utf-8') as f:
                compacted_messages = json.load(f)
            
            # 基于实际保存的消息重新估算 token
            post_compact_tokens = self._calculate_tokens(compacted_messages)
            
            if os.path.exists(meta_file_path):
                with open(meta_file_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
            else:
                meta = {
                    "session_id": "",
                    "created_at": time.time()
                }
            
            meta["total_tokens"] = post_compact_tokens
            meta["input_tokens"] = post_compact_tokens
            meta["output_tokens"] = 0
            meta["updated_at"] = time.time()
            
            with open(meta_file_path, 'w', encoding='utf-8') as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)
        except:
            pass

    def _split_into_rounds(self, messages):
        """
        将消息列表分割为对话轮次
        一轮对话定义：从一条 user 消息开始，包含随后的所有 assistant/tool 消息，
        直到遇到下一个 user 消息或历史结束
        """
        rounds = []
        current_round = []
        for msg in messages:
            if msg.get('role') == 'user':
                if current_round:
                    rounds.append(current_round)
                current_round = [msg]
            else:
                if not current_round and not rounds:
                    current_round = [msg]
                else:
                    current_round.append(msg)
        if current_round:
            rounds.append(current_round)
        return rounds

    def _clean_image_base64(self, messages):
        """
        清理消息中 image_url 的 base64 内容,避免总结时上下文过大
        将 base64 图片替换为占位描述,保留图片类型信息
        Args:
            messages: 消息列表(OpenAI格式)
        Returns:
            清理后的消息列表(深拷贝,不影响原始数据)
        """
        import copy
        cleaned_messages = copy.deepcopy(messages)
        
        for msg in cleaned_messages:
            content = msg.get('content')
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'image_url':
                        image_url = item.get('image_url', {})
                        url = image_url.get('url', '')
                        # 检测是否为 base64 格式
                        if url.startswith('data:image/'):
                            # 提取图片类型 (如 image/png)
                            mime_match = re.match(r'data:(image/\w+);base64,', url)
                            image_type = mime_match.group(1) if mime_match else 'image'
                            # 替换为占位描述
                            item['image_url'] = {
                                'url': '[图片已移除，原格式: ' + image_type + ']',
                                'detail': 'base64_image_removed'
                            }
        
        return cleaned_messages

    def get_message_rounds(self, messages):
        """获取消息的对话轮数"""
        return len(self._split_into_rounds(messages))

    def _generate_summary(self, messages_to_summarize):
        """
        调用AI生成对话摘要
        将压缩提示词作为system消息，历史消息作为对话内容发送给模型
        """
        compact_prompt = self._load_default_prompt()
        if self.system_prompt:
            compact_prompt = self.system_prompt + "\n\n" + compact_prompt

        summary_messages = [{"role": "system", "content": compact_prompt}] + [{"role": "user", "content": str(messages_to_summarize)}]
        
        import public

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=summary_messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=False,
                extra_body={
                    "enable_thinking": False
                }
            )
            summary = response.choices[0].message.content
            return self._format_summary(summary)
        except Exception as e:
            logging.error("ContextCompactor: 摘要生成失败: " + str(e))
            return None

    def _build_compacted_messages(self, summary):
        """
        构建压缩摘要消息
        """
        summary_prefix = "This session is being continued from a previous conversation that ran out of context. The summary below covers the earlier portion of the conversation.\n\n"
        full_summary = summary_prefix + "Summary:\n" + summary

        summary_msg = {
            "id": str(uuid.uuid4()),
            "role": "user",
            "content": full_summary,
            "timestamp": time.time(),
            "is_compact_summary": True
        }

        return summary_msg

    def _calculate_tokens(self, messages):
        """
        估算消息列表的token数
        使用精细化估算：
        - 1个汉字 ≈ 1.75 个 Token (取1.5-2的中间值)
        - 1个英文单词 ≈ 1.3 个 Token
        - 其他字符（标点、空格、符号等）≈ 0.25 个 Token
        """
        
        total_tokens = 0
        
        def estimate_text_tokens(text):
            """估算单段文本的token数"""
            if not text:
                return 0
            
            # 统计汉字数量
            chinese_chars = len(re.findall(r'[\u4e00-\u9fff\u3400-\u4dbf]', text))
            
            # 统计英文单词数量（按空格和标点分割）
            english_words = len(re.findall(r'[a-zA-Z]+', text))
            
            # 总字符数
            total_chars = len(text)
            
            # 其他字符（非汉字、非英文字母）
            other_chars = total_chars - chinese_chars - english_words
            
            # 估算token
            tokens = chinese_chars * 1.75 + english_words * 1.3 + other_chars * 0.25
            return int(tokens)
        
        for msg in messages:
            content = msg.get('content', '')
            if isinstance(content, str):
                total_tokens += estimate_text_tokens(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        total_tokens += estimate_text_tokens(item.get('text', ''))
                    elif isinstance(item, str):
                        total_tokens += estimate_text_tokens(item)
            
            # 统计思考内容
            reasoning_content = msg.get('reasoning_content', '')
            if reasoning_content:
                total_tokens += estimate_text_tokens(reasoning_content)
            
            # 工具调用估算
            if 'tool_calls' in msg:
                for tc in msg['tool_calls']:
                    func = tc.get('function', {})
                    tool_str = func.get('name', '') + ' ' + func.get('arguments', '')
                    total_tokens += estimate_text_tokens(tool_str)
            
            # 统计 tool_call_id
            tool_call_id = msg.get('tool_call_id', '')
            if tool_call_id:
                total_tokens += estimate_text_tokens(tool_call_id)
        
        return total_tokens

    def _format_summary(self, summary):
        """
        格式化摘要文本
        移除 <analysis> 思考过程，提取 <summary> 内容，清理多余空行
        """
        formatted = re.sub(r'<analysis>[\s\S]*?</analysis>', '', summary, flags=re.DOTALL)
        summary_match = re.search(r'<summary>([\s\S]*?)</summary>', formatted, re.DOTALL)
        if summary_match:
            content = summary_match.group(1).strip()
            formatted = re.sub(r'<summary>[\s\S]*?</summary>', content, formatted, flags=re.DOTALL)
        formatted = re.sub(r'\n{3,}', '\n\n', formatted).strip()
        return formatted

    def _load_default_prompt(self):
        """
        加载压缩提示词模板
        优先从 prompts/context_compact.md 读取，失败则使用默认提示
        """
        prompts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'prompts')
        prompt_file = os.path.join(prompts_dir, 'context_compact.md')
        if os.path.exists(prompt_file):
            try:
                with open(prompt_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                if content.startswith('---'):
                    match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)', content, re.DOTALL)
                    if match:
                        return match.group(2).strip()
                return content
            except:
                pass
        return "Summarize the conversation above in detail."

    @staticmethod
    def load_compact_config(prompts_dir=None):
        """
        加载压缩模板配置
        从 prompts/context_compact.md 读取 frontmatter 配置和提示词
        Args:
            prompts_dir: 提示词目录路径，为 None 则自动推断为插件 prompts 目录
        Returns:
            dict: 配置字典，包含 model_name、temperature、max_tokens、preserve_rounds、compact_instructions
        """
        if not prompts_dir:
            prompts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'prompts')

        import yaml as yaml_module
        compact_config = {}
        compact_prompt = ''

        for ext in ['.md', '.txt']:
            prompt_file = os.path.join(prompts_dir, "context_compact" + ext)
            if os.path.exists(prompt_file):
                try:
                    with open(prompt_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    if content.startswith('---'):
                        match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)', content, re.DOTALL)
                        if match:
                            frontmatter_str = match.group(1)
                            compact_prompt = match.group(2).strip()
                            try:
                                parsed_config = yaml_module.safe_load(frontmatter_str)
                                if isinstance(parsed_config, dict):
                                    compact_config.update(parsed_config)
                            except:
                                pass
                        else:
                            compact_prompt = content
                    else:
                        compact_prompt = content
                    break
                except:
                    pass

        if compact_prompt:
            compact_config['compact_instructions'] = compact_prompt

        return compact_config

    def _get_log_path(self, session_dir_path):
        """
        生成压缩日志文件路径
        使用时间戳生成唯一文件名：compact_YYYYMMDD_HHMMSS.log
        """
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(session_dir_path, "compact_" + timestamp + ".log")

    def _write_log(self, log_path, lines):
        """追加写入压缩日志文件"""
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                for line in lines:
                    f.write(line + "\n")
        except:
            pass

    def close(self):
        """关闭 OpenAI 客户端连接"""
        try:
            self.client.close()
        except:
            pass
