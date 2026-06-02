import json
import logging
import traceback
import threading
from typing import Generator, List, Dict, Any, Optional, Union
import openai
import uuid
import os
import platform
import datetime

import public
from mod.project.agent.chat_client.memory import MemoryManager
from mod.project.agent.chat_client.retrieval import RAGService, ExternalRAGService

from .tools import registry
from .tools.base import _xml_response

BINARY_EXTENSIONS = {
    '.zip', '.tar', '.gz', '.exe', '.dll', '.so', '.class', '.jar', '.war', '.7z',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg', '.mpg', '.mpeg',
    '.iso', '.bin', '.dat', '.db', '.sqlite', '.pyc', '.pyo'
}

class Agent:
    def __init__(self, session_id: str, config: Dict[str, Any] = None):
        self.session_id = session_id
        self.config = config or {}
        
        # 提取配置
        self.api_key = self.config.get("api_key")
        base_url = self.config.get("base_url")
        self.base_url = public.get_home_node(base_url) if base_url and 'bt.cn' in base_url else base_url
        self.model_name = self.config.get("model_name")
        self.rag_trigger_threshold = self.config.get("rag_trigger_threshold", 10)
        self.max_tool_iterations = self.config.get("max_tool_iterations", 10)
        self.enabled_tools = self.config.get("tools", [])
        self.default_headers = self.config.get("default_headers", {})
        self.system_prompt = self.config.get("system_prompt", "")
        self.temperature = self.config.get("temperature", 1)
        self.top_p = self.config.get("top_p", 1)
        
        # 官网知识库
        self.use_external_kb = self.config.get("use_external_kb", False)
        self.external_kb_appid = self.config.get("external_kb_appid", "bt_app_002")
        
        # Code mode configuration
        self.code_mode = self.config.get("code_mode", False)

        if self.code_mode:
            # Append environment info to system prompt
            self.current_dir = self.config.get("cwd")
            self.system_prompt += self._get_environment_info()
            
            # Default tools for code mode
            default_code_tools = [
                "Glob", "Grep", "LS", "Read", "Write", "DeleteFile",
                "SearchReplace", "StopCommand", "CheckCommandStatus", "RunCommand",
                "Task", "TodoWrite", "TodoRead", "TaskSummary", "WebFetch", "Skills"
            ]
            
            # Merge with existing enabled tools, avoiding duplicates
            for tool in default_code_tools:
                if tool not in self.enabled_tools:
                    self.enabled_tools.append(tool)
        else:
            # Default tools for non-code mode
            default_non_code_tools = [
                "Skills"
            ]
            for tool in default_non_code_tools:
                if tool not in self.enabled_tools:
                    self.enabled_tools.append(tool)

        self.memory = MemoryManager(
            session_id=session_id,
            sessions_dir=self.config.get("sessions_dir", "sessions"),
            sliding_window_size=self.config.get("sliding_window_size", 10),
            skill_agent_id=self.config.get("skill_agent_id"),
            model_name=self.model_name
        )
        
        # 将 MemoryManager 确定的 session_dir 传递给 RAGService
        self.rag = RAGService(
            session_dir=self.memory.session_dir,
            openai_api_key=self.api_key,
            openai_base_url=self.base_url,
            embedding_api_key=self.config.get("embedding_api_key"),
            embedding_base_url=self._process_url(self.config.get("embedding_base_url")),
            embedding_model_name=self.config.get("embedding_model_name"),
            small_model_name=self.config.get("small_model_name"),
            rag_retrieval_count=self.config.get("rag_retrieval_count", 10),
            rag_final_count=self.config.get("rag_final_count", 5),
            default_headers=self.default_headers
        )

        # 全局的知识库 RAG Service
        self.global_rag=None
        if self.use_external_kb:
            self.global_rag = ExternalRAGService(
                enable_rag_judgment=self.config.get("enable_rag_judgment", True),
                default_headers=self.default_headers
            )

        self.client = openai.OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            default_headers=self.default_headers
        )

    def _process_url(self, url):
        if url and 'bt.cn' in url:
            return public.get_home_node(url)
        return url

    def _get_environment_info(self) -> str:
        """Constructs environment information string to append to system prompt."""
        cwd = self.current_dir
        if os.path.exists(cwd):
            is_git = os.path.isdir(os.path.join(cwd, ".git"))
        else:
            is_git = False
        plat = platform.system().lower()
        today = datetime.date.today().strftime("%Y-%m-%d")
        
        # Note: model info is usually handled by the caller/config,
        # but we can try to include what we have.
        # The prompt template requested:
        # You are powered by the model named ${model.api.id}. The exact model ID is ${model.providerID}/${model.api.id}
        
        env_info = f"""

You are powered by the model named {self.model_name}.

Here is some useful information about the environment you are running in:
<env>
  Working directory: {cwd}
  Is directory a git repo: {"yes" if is_git else "no"}
  Platform: {plat}
  Today's date: {today}
</env>
<directories>
</directories>
"""
        return env_info

    def _is_binary_file(self, file_path: str) -> bool:
        """检查文件是否为二进制文件"""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in BINARY_EXTENSIONS:
            return True
        
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                if b'\x00' in chunk:
                    return True
        except:
            pass
        return False

    def _process_site_reference(self, site_name: str) -> tuple:
        """
        处理网站引用，返回 (call_prompt, result) 元组
        """
        call_prompt = f'[系统预处理] 检测到用户提到网站 "{site_name}"，已自动从数据库获取该网站的基础信息：'
        try:
            site_info = public.M('sites').where('name=?', (site_name,)).field('name,path,status,project_type,project_config').find()
            
            if not site_info:
                result = f'未找到网站: {site_name}'
            else:
                status_text = '开启' if site_info.get('status') == '1' else '关闭'
                result = f"网站基础信息:\n"
                result += f"- 网站名称(name): {site_info.get('name', '')}\n"
                result += f"- 项目路径(path): {site_info.get('path', '')}\n"
                result += f"- 网站状态(status): {status_text} (1=开启, 0=关闭)\n"
                result += f"- 项目类型(project_type): {site_info.get('project_type', 'PHP')}\n"
                result += f"- 项目配置(project_config): {site_info.get('project_config', '{}')}\n"
                result += f"\n字段说明:\n"
                result += f"- path: 网站项目路径\n"
                result += f"- status: 网站状态，1为开启状态，0为关闭状态\n"
                result += f"- project_type: 项目类型，如PHP、Java、Node等等\n"
                result += f"- project_config: 项目的额外配置，如果是需要启动的项目通常包含启动命令等信息，如果是静态或PHP项目通常为空\n"
        except Exception as e:
            result = f'获取网站信息失败: {str(e)}'
        
        return (call_prompt, result)

    def _process_file_reference(self, file_path: str) -> tuple:
        """
        处理单个文件引用，返回 (call_prompt, result) 元组
        """
        if not os.path.exists(file_path):
            return (
                f'Called the Read tool with the following input: {{"filePath":"{file_path}"}}',
                f'ERROR: 文件路径不存在: {file_path}'
            )
        
        if os.path.isdir(file_path):
            call_prompt = f'Called the LS tool with the following input: {{"path":"{file_path}"}}'
            try:
                from .tools.agent_tools import LS
                result = LS(path=file_path)
            except Exception as e:
                result = f'ERROR: 读取文件夹失败: {str(e)}'
            return (call_prompt, result)
        
        if self._is_binary_file(file_path):
            return (
                f'Called the Read tool with the following input: {{"filePath":"{file_path}"}}',
                f'ERROR: 当前是二进制文件还不支持读取: {file_path}'
            )
        
        call_prompt = f'Called the Read tool with the following input: {{"filePath":"{file_path}"}}'
        try:
            from .tools.agent_tools import Read
            result = Read(file_path=file_path)
        except Exception as e:
            result = f'ERROR: 读取文件失败: {str(e)}'
        return (call_prompt, result)

    def _process_user_input_files(self, user_input: Union[str, List[Dict[str, Any]]]) -> Union[str, List[Dict[str, Any]]]:
        """
        处理用户输入中的文件引用，将文件内容追加到 content 列表中
        """
        if isinstance(user_input, str):
            return user_input

        if not isinstance(user_input, list):
            return user_input

        file_refs = [item for item in user_input if isinstance(item, dict) and item.get("type") == "file"]
        site_refs = [item for item in user_input if isinstance(item, dict) and item.get("type") == "site"]

        if not file_refs and not site_refs:
            return user_input

        new_content = list(user_input)

        for file_ref in file_refs:
            file_path = file_ref.get("path", "")
            if not file_path:
                continue

            call_prompt, result = self._process_file_reference(file_path)

            new_content.append({
                "type": "text",
                "text": call_prompt
            })
            new_content.append({
                "type": "text",
                "text": result
            })

        for site_ref in site_refs:
            site_name = site_ref.get("name", "") or site_ref.get("path", "")
            if not site_name:
                continue

            call_prompt, result = self._process_site_reference(site_name)

            new_content.append({
                "type": "text",
                "text": call_prompt
            })
            new_content.append({
                "type": "text",
                "text": result
            })

        return new_content

    def close(self):
        """
        关闭 Agent，释放资源。
        """
        self.rag.close()
        if self.global_rag:
            self.global_rag.close()
        self.client.close()

    def _create_completion_stream(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]]):

        params = {
            "model": self.model_name,
            "messages": messages,
            "tools": tools if tools else None,
            "stream": True,
            "stream_options": {"include_usage": True},
            "temperature": self.temperature,
            "top_p": self.top_p,
            "extra_body": {}
        }

        thinking = self.config.get("thinking", False)
        web_search = self.config.get("web_search", False)

        if "qwen" in str(self.model_name).lower() or "default" in str(self.model_name).lower():
            params["extra_body"]["enable_thinking"] = thinking
            params["extra_body"]["enable_search"] = web_search
            params["extra_body"]["search_options"] = {
                "search_strategy": "max",       # 配置搜索策略为高性能模式
                "enable_search_extension": True # 垂直领域搜索增强 例如天气、股市等
            }
        
        if "doubao" in str(self.model_name).lower():
            enable_type = "enabled" if thinking else "disabled"
            params['extra_body']["thinking"] = {
                "type": enable_type
            }

        return self.client.chat.completions.create(**params)

    def chat(self, user_input: Union[str, List[Dict[str, Any]]]) -> Generator[Dict[str, Any], None, None]:
        """
        主聊天循环，支持流式响应。
        """
        try:
            # 生成 ID
            user_msg_id = str(uuid.uuid4())
            ai_msg_id = str(uuid.uuid4())

            yield {
                "type": "meta_info",
                "user_msg_id": user_msg_id,
                "ai_msg_id": ai_msg_id
            }
            
            # 处理文件引用
            user_input = self._process_user_input_files(user_input)
            
            # 1. 更新记忆 (用户)
            user_msg = self.memory.add_message("user", user_input, id=user_msg_id)
            
            # 2. 检索上下文 (RAG)
            context_str = ""
            
            # 提取纯文本用于检索
            user_text = user_input
            if isinstance(user_input, list):
                # logging.info(user_input)
                text_parts = []
                for item in user_input:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                user_text = "\n".join(text_parts)
                
            # 全局上下文检索（ExternalRAGService 内部会判断是否需要检索）
            # 获取最近的对话历史用于 RAG 判断
            recent_history = self.memory.get_sliding_window()
            if self.global_rag:
                global_docs = self.global_rag.search(
                    user_text,
                    scope="global",
                    session_history=recent_history,
                    # enable_rag_judgment=False # 关闭模型检索校验(先让小模型来判断是否需要进行rag),
                )
                if global_docs:
                    context_str += "[以下 <knowledge_base> 标签内的内容仅作为备选参考资料。]:\n" + "\n<knowledge_base>".join(global_docs) + "</knowledge_base>\n\n"

            # 检查触发条件
            if self.memory.get_total_rounds() > self.rag_trigger_threshold:
                
                # 排除当前滑动窗口中的 ID 以避免重复
                sliding_window = self.memory.get_sliding_window()
                exclude_ids = [m["id"] for m in sliding_window]
                
                # 传递 session_id 进行隔离。
                retrieved_docs = self.rag.search(
                    user_text,
                    session_id=self.session_id,
                    scope="session",
                    exclude_ids=exclude_ids
                )
                if retrieved_docs:
                    if context_str:
                         context_str += "[Session History(for reference only)]:\n"
                    context_str += "\n".join(retrieved_docs)

            # 3. 构建消息 Todo
            
            # 自动压缩检查（预留代码位置，当前未启用）
            # if self.memory.check_auto_compact(max_context_tokens):
            #     from mod.project.agent.chat_client.context_compactor import ContextCompactor
            #     compactor = ContextCompactor(client=self.client, config={
            #         "model_name": self.model_name,
            #         "temperature": 0.3,
            #         "max_tokens": 4096,
            #         "preserve_rounds": 3,
            #     })
            #     compacted_messages, summary, pre_tokens, post_tokens = compactor.compact(self.memory.get_full_history())
            #     if compacted_messages:
            #         self.memory.compact_messages(compacted_messages[0], compacted_messages[1], [])
            
            messages = self._build_messages(context_str)
            
            # 工具配置
            tools = registry.get_openai_tools(enabled_ids=self.enabled_tools)
            
            # 循环限制，防止无限递归
            iteration_count = 0
            full_response_content = "" # 最终累积响应
            full_reasoning_content = "" # 最终累积思考
            tool_call_chunks = {} # Initialize to ensure scope availability
            
            total_usage = {
                "total_tokens": 0,
                "input_tokens": 0,
                "output_tokens": 0
            }
            last_message_id = ""

            while iteration_count < self.max_tool_iterations:
                iteration_count += 1
                
                # Reset last_loop_tokens for this iteration
                last_loop_tokens = {
                    "total_tokens": 0,
                    "input_tokens": 0,
                    "output_tokens": 0
                }
                
                # Copy messages to avoid polluting history with ephemeral warnings
                request_messages = list(messages)

                if iteration_count > 1:
                    remaining = self.max_tool_iterations - iteration_count + 1
                    iter_msg = f"\n<system-reminder>Action Count: {iteration_count}/{self.max_tool_iterations}. "
                    if remaining <= 2:
                        iter_msg += "WARNING: You are approaching the tool execution limit. If the task is not finished, STOP NOW and ask the user to continue in the next turn to reset the counter. Do NOT try to rush."
                    else:
                        iter_msg += "Proceed efficiently."
                    iter_msg += "<system-reminder>"
                    
                    # Append as a temporary system message for this request only
                    request_messages.append({"role": "system", "content": iter_msg})
                
                response_stream = self._create_completion_stream(request_messages, tools)
                # 工具调用累加器
                tool_call_chunks = {}
                reported_tool_indices = set()
                current_response_content = ""
                current_reasoning_content = ""

                for chunk in response_stream:
                    # 计算token花费
                    if chunk.usage:
                        total_usage["total_tokens"] += chunk.usage.total_tokens
                        total_usage["input_tokens"] += chunk.usage.prompt_tokens
                        total_usage["output_tokens"] += chunk.usage.completion_tokens
                        
                        last_loop_tokens["total_tokens"] = chunk.usage.total_tokens
                        last_loop_tokens["input_tokens"] = chunk.usage.prompt_tokens
                        last_loop_tokens["output_tokens"] = chunk.usage.completion_tokens
                        
                        last_message_id = chunk.id
                    # 结束判断
                    if not chunk.choices:
                        continue

                    delta = chunk.choices[0].delta
                    
                    # 处理推理内容
                    if getattr(delta, "reasoning_content", None):
                        current_reasoning_content += delta.reasoning_content
                        yield {
                            "type": "reasoning",
                            "response": delta.reasoning_content
                        }

                    # 处理正文内容
                    if delta.content:
                        current_response_content += delta.content
                        yield {
                            "type": "content",
                            "response": delta.content
                        }
                    
                    # 处理工具调用
                    if delta.tool_calls:
                        for tc in delta.tool_calls:
                            index = tc.index
                            if index not in tool_call_chunks:
                                tool_call_chunks[index] = {
                                    "id": tc.id,
                                    "function": {"name": "", "arguments": ""}
                                }
                            
                            if tc.id:
                                tool_call_chunks[index]["id"] = tc.id
                            if tc.function.name:
                                tool_call_chunks[index]["function"]["name"] += tc.function.name
                            if tc.function.arguments:
                                tool_call_chunks[index]["function"]["arguments"] += tc.function.arguments
                            
                            tool_name = tool_call_chunks[index]["function"]["name"]
                            if index not in reported_tool_indices and tool_name and tool_call_chunks[index]["function"]["arguments"]:
                                reported_tool_indices.add(index)
                                tool_exists = registry.tool_exists(tool_name)
                                tool_enabled = registry.is_tool_enabled(tool_name, self.enabled_tools) if tool_exists else False
                                if tool_exists and tool_enabled:
                                    yield {
                                        "type": "tool_call",
                                        "tool": tool_name,
                                        "args": {},
                                        "id": tool_call_chunks[index]["id"]
                                    }

                # 如果这一轮有内容，累加到最终响应
                if current_response_content:
                    full_response_content = current_response_content
                if current_reasoning_content:
                    full_reasoning_content = current_reasoning_content

                # 如果没有工具调用，结束循环
                if not tool_call_chunks:
                    yield {
                        "type": "stop",
                        "usage": total_usage,
                        "message_id": last_message_id
                    }
                    break

                # 处理工具调用逻辑
                assistant_msg_kwargs = {"tool_calls": []}
                for idx in sorted(tool_call_chunks.keys()):
                    tc = tool_call_chunks[idx]
                    assistant_msg_kwargs["tool_calls"].append({
                        "id": tc["id"],
                        "type": "function",
                        "function": tc["function"]
                    })
                
                # 保存助手工具调用消息
                if current_reasoning_content:
                    assistant_msg_kwargs["reasoning_content"] = current_reasoning_content
                
                self.memory.add_message("assistant", current_response_content,id=ai_msg_id, **assistant_msg_kwargs)
                
                messages.append({
                    "role": "assistant",
                    "content": current_response_content,
                    "reasoning_content": current_reasoning_content,
                    "tool_calls": assistant_msg_kwargs["tool_calls"]
                })

                # 执行工具
                for tc in assistant_msg_kwargs["tool_calls"]:
                    func_name = tc["function"]["name"]
                    args_str = tc["function"]["arguments"]
                    call_id = tc["id"]
                    
                    tool_exists = registry.tool_exists(func_name)
                    tool_enabled = registry.is_tool_enabled(func_name, self.enabled_tools) if tool_exists else False
                    
                    #处理不存在的工具
                    if not tool_exists:
                        result_str = _xml_response(func_name, "error", f"Error: Tool '{func_name}' does not exist.")
                        content_structure = [{"type": "text", "text": result_str}]
                        self.memory.add_message("tool", content_structure, tool_call_id=call_id, id=ai_msg_id)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": content_structure
                        })
                        continue
                    
                    #处理未启用的工具
                    if not tool_enabled:
                        tool_id = registry.get_tool_id(func_name)
                        result_str = _xml_response(func_name, "error", f"Error: Tool '{func_name}' (ID: {tool_id}) is not enabled. You do not have permission to use this tool.")
                        content_structure = [{"type": "text", "text": result_str}]
                        self.memory.add_message("tool", content_structure, tool_call_id=call_id, id=ai_msg_id)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": content_structure
                        })
                        continue
                    
                    yield {
                        "type": "tool_call",
                        "tool": func_name,
                        "args": args_str,
                        "id": call_id
                    }
                    try:
                        args = json.loads(args_str)
                        
                        # Special handling for Task tool to inherit config
                        if func_name == "Task":
                            # Create a copy of config to avoid modification
                            agent_config = self.config.copy()
                            # Remove specific keys that shouldn't be inherited or will be overridden
                            agent_config.pop("system_prompt", None)
                            agent_config.pop("tools", None)
                            
                            # Inject into args
                            args["parent_config"] = agent_config
                            args["parent_session_id"] = self.session_id
                        
                        # Inject session_id for Todo and Summary tools
                        if func_name in ["TodoWrite", "TodoRead", "TaskSummary"]:
                            args["session_id"] = self.session_id
                            args["sessions_dir"] = self.config.get("sessions_dir")

                        func = registry.get_tool_func(func_name)
                        if func:
                            result_str = func(**args)
                        else:
                            result_str = _xml_response(func_name, "error", f"Error: Tool {func_name} not found.")
                    except Exception as e:
                        result_str = _xml_response(func_name, "error", f"Error executing tool: {str(e)}")
                    
                    yield {
                        "type": "tool_result",
                        "tool": func_name,
                        "result": result_str,
                        "id": call_id
                    }
                    
                    # Construct content with XML structure
                    content_structure = [
                        {
                            "type": "text",
                            "text": result_str
                        }
                    ]
                    
                    # Add to memory with new structure
                    self.memory.add_message("tool", content_structure, tool_call_id=call_id, id=ai_msg_id)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": content_structure
                    })
                # 检测上下文是否超过最大token数
                max_context_tokens = self.config.get("max_context_tokens", 64000)
                current_context_tokens = total_usage.get("input_tokens", 0)
                
                if last_loop_tokens['input_tokens'] >= max_context_tokens:
                    yield {
                        "type": "error",
                        "data": "上下文已超过最大Token限制，为避免信息丢失，请压缩上下文后再继续对话"
                    }
                    break
                
            # 6. 最终记忆更新 (助手响应)
            if not tool_call_chunks and full_response_content:
                 kwargs = {}
                 if full_reasoning_content:
                     kwargs["reasoning_content"] = full_reasoning_content
                 
                 # 使用预生成的 ai_msg_id
                 ai_msg = self.memory.add_message("assistant", full_response_content, id=ai_msg_id, **kwargs)
                 
                 # 7. 异步向量化
                 t = threading.Thread(
                     target=self.rag.add_memory,
                     args=(user_msg, ai_msg, self.session_id)
                 )
                 t.start()
                
            if iteration_count >= self.max_tool_iterations:
                yield {"type": "error", "data": "达到最大行动次数上限，已强制停止当前对话 error_code:max_tool_iterations"}

            
            # 更新 meta.json 中的 token 使用量
            self.memory.update_meta_tokens(
                total_tokens=last_loop_tokens["total_tokens"],
                input_tokens=last_loop_tokens["input_tokens"],
                output_tokens=last_loop_tokens["output_tokens"]
            )
            
            # 发送 meta_info 包含 ID 和最后一次 agent loop 的 token 使用
            yield {
            "type": "meta_info",
            "user_msg_id": user_msg_id,
            "ai_msg_id": ai_msg_id,
            "last_loop_tokens": last_loop_tokens
            }
            
        except openai.AuthenticationError as e:
            yield {"type": "error", "data": f"API密钥错误或无效，请检查密钥是否正确:{e}"}
        except openai.RateLimitError as e:
            yield {"type": "error", "data": "接口调用频率超限，请稍后再试或提升配额:{}".format(e)}
        except openai.APIConnectionError as e:
            yield {"type": "error", "data": f"无法连接到API服务器（{self.base_url}），请检查网络或地址是否正确:{e}"}
        except openai.APIError as e:
            yield {"type": "error", "data": f"API返回错误：{str(e)}"}
        except Exception as e:
            logging.error(f"Unexpected error in Agent.chat: {traceback.format_exc()}")
            yield {"type": "error", "data": f"调用AI接口时发生未知错误：{str(e)}"}
    
    def _filter_file_blocks(self, content: Union[str, List[Dict[str, Any]]]) -> Union[str, List[Dict[str, Any]]]:
        """
        过滤掉 type="file" 和 type="site" 的块，只保留 type="text" 的块
        """
        if isinstance(content, str):
            return content
        
        if not isinstance(content, list):
            return content
        
        FILTERED_TYPES = {"file", "site"}
        return [item for item in content if not (isinstance(item, dict) and item.get("type") in FILTERED_TYPES)]

    def _build_messages(self, context_str: str) -> List[Dict[str, Any]]:
        """构建包含系统指令、上下文和滑动窗口的 Prompt。"""
        
        if context_str:
            self.system_prompt += f"\n\n[History Context (Time-Ordered)]:\n{context_str}"
            
        messages = [{"role": "system", "content": self.system_prompt}]
        
        window = self.memory.get_sliding_window()
        for msg in window:
            content = msg["content"]
            content = self._filter_file_blocks(content)
            
            m = {
                "role": msg["role"],
                "content": content
            }
            if "tool_calls" in msg:
                m["tool_calls"] = msg["tool_calls"]
            if "tool_call_id" in msg:
                m["tool_call_id"] = msg["tool_call_id"]
            if msg.get("role") == "assistant" and "reasoning_content" in msg:
                m["reasoning_content"] = msg["reasoning_content"]
            messages.append(m)
            
        return messages
