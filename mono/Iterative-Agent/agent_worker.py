import logging
import json
import demjson
import re
import os
from datetime import datetime
from typing import TypedDict, Optional, List, Dict, Any, Callable
import inspect
import unittest
from pathlib import Path
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from urllib.parse import urlparse
import yaml
import sys
import time


from logging_helper import global_logger
from agent_selftools import LangTools
from agent_utils import filter_analysis_history, save_result_to_json, process_and_label_context

os.environ['TAVILY_API_KEY'] = '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'
os.environ['OPENAI_API_BASE'] = "http://127.0.0.1:8081/v1"
os.environ['OPENAI_API_KEY'] = "aaaa"
logger = global_logger

MODEL = "Qwen/Qwen3-32B"
TOOL_BASE_URL = "http://127.0.0.1:8081/v1"

class AgentState(TypedDict):
    project_dir: str  # input data
    patch: dict  # file_path, patch
    description: str
    msg: str
    root_cause: str
    confidence_score: float

    joern: bool = 0  # Joern state, which indicates if the project has been initialized
    file_cache: List = []  # Joern file cache, help hit the file path
    cpg_file: str = None  # Joern CPG file
    base_url: str = None  # Joern Server URL
    prompt_version: str = "default"  # prompt version

    enriched_data: List[dict] = []  # more context data
    analysis: Optional[dict] = {}  # analysis result
    iteration: int = 0
    need_context: bool = True  # flag to indicate if more context is needed
    history: List[dict] = []  # LLM analysis history and context collection
    debug_trace: List[str] = []  # debug trace
    status: Optional[str] = None  # status trace
    error: Optional[str] = None

def load_yaml(file_path: str) -> dict:
    with open(file_path, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

initial_analysis_template = load_yaml("./prompt/initial_analysis.yaml")
root_cause_analysis_template = load_yaml("./prompt/root_cause_analysis.yaml")
actor_prompt = load_yaml("./prompt/actor_tools.yaml")

PROMPT_VERSION_MAP = {
    "default": (initial_analysis_template['initial_analysis_prompt_rigorous'], root_cause_analysis_template['root_cause_analysis_prompt_rigorous'], actor_prompt['actor_tools_prompt']),
    "pragmatic": (initial_analysis_template['initial_analysis_prompt_pragmatic'], root_cause_analysis_template['root_cause_analysis_prompt_pragmatic'], actor_prompt['actor_tools_prompt']),
    "limited": (initial_analysis_template['initial_analysis_prompt_limited_rigorous'], root_cause_analysis_template['root_cause_analysis_prompt_limited_rigorous'], actor_prompt['actor_limited_tools_prompt']),
}


_CTRL_RE = re.compile(r"[\x00-\x1F]")
_KEY_FIX_RE = re.compile(r"([{,]\s*)([A-Za-z_][A-Za-z_0-9]*)\s*:\s*")

_CURLY_QUOTES = {
    "\u201c": '"',  # “ → "
    "\u201d": '"',  # ” → "
    "\u2018": "'",  # ‘ → '
    "\u2019": "'",  # ’ → '
}
class JsonRepairHelper:
    """
    Attempts to parse malformed JSON by repairing common issues or using an LLM fallback.
    """
    def __init__(self, api_config: Optional[Dict] = None):
        config = api_config or {}
        self.llm = ChatOpenAI(
            # model="deepseek-ai/DeepSeek-V3",
            model=MODEL,
            temperature=0.2,
            timeout=None,
            api_key=config.get("api_key"),
            base_url=TOOL_BASE_URL
        )

    def safe_parse_json(self, content: str, *, strict: bool = False) -> dict:
        """Return a Python object or ``None`` when every repair attempt fails."""
        # 0. Fast path – may succeed for 80‑90 % of inputs.
        try:
            return json.loads(content.replace('\\','\\\\'), strict=False)
        except json.JSONDecodeError as exc:
            global_logger.debug("Initial JSON parsing failed: %s", exc)
            
        # 1. Pre‑clean: strip BOM, normalise quotes, escape ctrl chars.
        cleaned = self._preclean(content)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            global_logger.debug("stage 1 – after _preclean(): %s", exc)

        # 2. Structural patch (non‑destructive).
        patched = self._structural_fix(cleaned)
        try:
            return json.loads(patched)
        except json.JSONDecodeError as exc:
            global_logger.debug("stage 2 – after _structural_fix(): %s", exc)
        # 3. demjson fallback, if available.
        if demjson is not None:
            try:
                return demjson.decode(content)  # type: ignore[arg-type]
            except Exception as exc:  # pragma: no cover
                global_logger.debug("stage 3 – after demjson.decode(): %s", exc)
        # 4. LLM repair.
        if self.llm is not None:
            try:
                return self._llm_fix_json(content)
            except json.JSONDecodeError as exc:  # pragma: no cover
                global_logger.debug("stage 4 – after LLM repair: %s", exc)

        if strict:
            raise json.JSONDecodeError("Unrecoverable JSON", content, 0)
        return None


    def _preclean(self, raw: str) -> str:
        if raw.startswith("\ufeff"):
            raw = raw[1:]
        raw = "".join(_CURLY_QUOTES.get(ch, ch) for ch in raw)

        def _esc(m: re.Match[str]) -> str:
            return f"\\u{ord(m.group()):04x}"

        return _CTRL_RE.sub(_esc, raw)

    def _structural_fix(self, raw: str) -> str:
        raw += "}" * (raw.count("{") - raw.count("}"))
        raw += "]" * (raw.count("[") - raw.count("]"))
        raw = _KEY_FIX_RE.sub(r'\1"\2": ', raw)
        return raw

    def _llm_fix_json(self, malformed_json: str, retry = 1) -> Optional[Any]:
        if retry > 3:
            logger.error(f"[JSON ERROR] LLM failed to repair JSON after 3 attempts: {malformed_json}")
            return None
        prompt = (
            f"This is Json {retry} Times:\n You are a strict JSON repair agent. Your job is to fix the given malformed JSON.\n"
            "- Return ONLY valid JSON (object `{...}` or array `[...]`).\n"
            "- Do NOT include any explanation or markdown formatting.\n"
            "- Ensure correct quotes, colons, commas, and brackets.\n\n"
            "- Only one Json object is allowed to be returned. Do not modify any key content."
            "Malformed JSON:\n"
            f"{malformed_json.strip()}\n"
        )
        try:
            response = self.llm.invoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)
            content = re.sub(r"```(?:json)?\s*([\s\S]*?)\s*```", r"\1", content).strip()
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                retry += 1
                return self._llm_fix_json(content, retry)
        except Exception as e:
            logger.error(f"[JSON ERROR] LLM failed to repair JSON: {str(e)}\n{malformed_json}")
            return None
        

class ContextCheckerLLM:
    def __init__(self, api_config: Optional[Dict] = None):
        config = api_config or {}
        self.llm = ChatOpenAI(
            model=config.get("model", "deepseek-ai/DeepSeek-V3"),
            temperature=0.6,
            timeout=None,
            api_key=config.get("api_key"),
            base_url=config.get("base_url")
        )
        self.json_helper = JsonRepairHelper(api_config)

    def evaluate(self, required_context: str, tool_outputs: List[Dict]) -> Dict:
        """
        Evaluate a batch of tool outputs.
        Each item must have: { "id": int, "tool": str, "result": any }
        Returns:
            {
              "result_comment": "...",
              "evaluations": [
                {"id": 0, "is_valid": true},
                {"id": 1, "is_valid": false},
                ...
              ]
            }
        """
        examples = [
            {
                "id": item["id"],
                "tool": item.get("tool", "N/A"),
                "result_preview": str(item.get("result", ""))[:300]
            }
            for item in tool_outputs
        ]

        prompt = CONTEXT_CHECKER_PROMPT_TEMPLATE.format(
            required_context=required_context,
            tool_outputs=json.dumps(examples, indent=2)
        )

        response = self.llm.invoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        content = re.sub(r"```(?:json)?\s*", "", content).strip().rstrip("```")
        parsed = self.json_helper.safe_parse_json(content)

        if not isinstance(parsed, dict) or "evaluations" not in parsed:
            logger.warning("[CheckerLLM] Invalid response structure.")
            return {
                "result_comment": "Checker failed to respond with correct format.",
                "evaluations": []
            }

        return {
            "result_comment": parsed.get("result_comment", ""),
            "evaluations": parsed["evaluations"]
        }



class VulnerabilityCritic:
    """
    Performs initial and root cause analysis using LLM, backed with prompt templates and JSON validation.
    """

    def __init__(self, api_config: Optional[Dict] = None, prompt_version: str = "default"):
        config = api_config or {}
        self.llm = ChatOpenAI(
            model=config.get("model", "deepseek-ai/DeepSeek-V3"),
            temperature=config.get("temperature", 0.6),
            timeout=None,
            api_key=config.get("api_key"),
            base_url=config.get("base_url")
        )
        self.prompt_version = prompt_version
        self.json_helper = JsonRepairHelper(api_config)

        if self.prompt_version not in PROMPT_VERSION_MAP:
             logger.warning(f"Prompt version '{self.prompt_version}' not found. Falling back to 'default'.")
             self.prompt_version = "default"

        self._initial_prompt = PROMPT_VERSION_MAP[self.prompt_version][0]
        self._root_cause_prompt = PROMPT_VERSION_MAP[self.prompt_version][1]

    def analyze_initial(self, state: Dict) -> Dict:
        try:
            prompt = self._initial_prompt.format(**state)
            raw_response = self._get_llm_response(prompt)
            logger.info(f"[Initial analysis response] \n{raw_response}")
            return self._validate_response(raw_response, state, is_initial=True), prompt
        except Exception as e:
            return self._error_response("[Analysis ERROR] Initial analysis failed", state, e), prompt

    def determine_root_cause(self, state: Dict) -> Dict:
        try:
            filtered_history = filter_analysis_history(state["history"])

            prompt = self._root_cause_prompt.format(
                description=state["description"],
                msg=state["msg"],
                patch=state["patch"],
                history_summary=json.dumps(filtered_history, indent=2),
                # current_context=last_context
            )
           #  print(f"prompt: {prompt}")
           #  input()
            raw_response = self._get_llm_response(prompt)
            return self._validate_response(raw_response, state, is_initial=False), prompt
        except Exception as e:
            return self._error_response("[Analysis ERROR] Root cause analysis failed", state, e), prompt

    def _get_llm_response(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        content = response.content if hasattr(response, 'content') else str(response)
        start_marker = '```json'
        end_marker = '```'
        start = content.find(start_marker)
        end = content.find(end_marker, start + len(start_marker))
        # \n</think>\n\n
        if start != -1 and end != -1:
            json_content = content[start + len(start_marker):end].strip()
        else:
            start_marker = '<think>'
            end_marker = '</think>'
            start = content.find(start_marker)
            end = content.find(end_marker, start + len(start_marker))
            if start != -1 and end != -1:
                json_content = content[end + len(end_marker):].strip()
            else:
                json_content = content.strip()
        return json_content

    def _validate_response(self, raw: str, state: Dict, is_initial: bool) -> Dict:
        try:
            data = self.json_helper.safe_parse_json(raw)
            if data is None:
                raise ValueError(f"[JSON ERROR] Failed to parse JSON response\n {raw}")
            if not isinstance(data, dict):
                raise ValueError(f"[JSON ERROR] Expected JSON object but got something else\n {raw}")

            if "confidence_score" in data:
                if not 0 <= data["confidence_score"] <= 1:
                    raise ValueError("Confidence score out of range")

            required_fields = (
                ["language", "vulnerability_type", "repair_strategy", "need_context"]
                if is_initial else
                ["root_cause"]
            )
            for field in required_fields:
                if field not in data:
                    raise ValueError(f"[JSON ERROR] Missing required field: {field}\n {raw}")

            return data
        except Exception as e:
            raise ValueError(f"[JSON ERROR] Invalid JSON response format: {str(e)}\n {raw}")

    def _error_response(self, reason: str, state: Dict, error: Exception) -> Dict:
        logger.error(f"{reason}: {str(error)}")
        return {
            "status": "error",
            "reason": reason,
            "error_details": str(error),
            "timestamp": datetime.now().isoformat(),
            "iteration": state.get("iteration", 0),
            "debug_trace": state.get("debug_trace", []) + [f"Error in {self._current_method()}"]
        }

    def _current_method(self) -> str:
        return inspect.currentframe().f_back.f_back.f_code.co_name

class LLMActor:
    """
    LLM actor responsible for translating required context into tool queries
    using a language model and parsing its output as tool parameter sets.
    """
    def __init__(self, api_config: Optional[Dict] = None, prompt_version: str = "default"):
        config = api_config or {}
        self.llm = ChatOpenAI(
            # model="deepseek-ai/DeepSeek-V3",
            model=MODEL,
            temperature=0.1,
            timeout=None,
            api_key=config.get("api_key"),
            base_url=TOOL_BASE_URL
        )
        self.prompt_version = prompt_version
        self.json_helper = JsonRepairHelper(api_config)

        if self.prompt_version not in PROMPT_VERSION_MAP:
             logger.warning(f"Prompt version '{self.prompt_version}' not found. Falling back to 'default'.")
             self.prompt_version = "default"
        self.tool_prompt = PROMPT_VERSION_MAP[self.prompt_version][2]

    def generate_tools_query(self, required_context: str) -> List[Dict]:
        try:
            prompt = self.tool_prompt.format(request=required_context)
            raw_output = self._get_llm_response(prompt)
            parsed = self.json_helper.safe_parse_json(raw_output)

            if isinstance(parsed, dict):
                return [parsed]
            elif isinstance(parsed, list):
                return parsed
            else:
                logger.error("[JSON ERROR] Unexpected JSON structure from LLM.")
                return []
        except Exception as e:
            logger.error(f"[Tools ERROR] Tool query generation failed: {str(e)}")
            return []

    def _get_llm_response(self, prompt: str) -> str:
        response = self.llm.invoke(prompt)
        content = response.content if hasattr(response, 'content') else str(response)
        start_marker = '```json'
        end_marker = '```'
        start = content.find(start_marker)
        end = content.find(end_marker, start + len(start_marker))
        if start != -1 and end != -1:
            json_content = content[start + len(start_marker):end].strip()
        else:
            start_marker = '<think>'
            end_marker = '</think>'
            start = content.find(start_marker)
            end = content.find(end_marker, start + len(start_marker))
            if start != -1 and end != -1:
                json_content = content[end + len(end_marker):].strip()
            else:
                json_content = content.strip()
        return json_content

class ContextActor:
    """
    Uses tool execution (Joern or Tree-sitter based) to collect contextual information
    about functions or files relevant to the patch being analyzed.
    """
    def __init__(self, project_dir: str, api_config: Dict = None, joern_state: bool = 0, file_cache: List = None, base_url: str = None, prompt_version: str = "default"):
        """
        Initialize the ContextActor with project directory and optional file name.
        """
        self.prompt_version = prompt_version
        self.api_config = api_config
        self.project_dir = project_dir
        self.file_cache = file_cache  # Cache for file paths from Joern, when we preprocess we have
        self.pro_id = None      # Project ID from Joern
        self.Ltools = LangTools(base_url=base_url)
        self.base_url = base_url
        if self.Ltools.check_joern():
            global_logger.info(f"{base_url} Joern service is available")
        if not joern_state: # make sure only import one time
            self._init_project(project_dir)  
            if self.pro_id is None:
                raise ValueError(f"Failed to initialize Joern project: {project_dir}")
            logger.info(f"{base_url}: Context actor work for {project_dir} with id {self.pro_id}")

    def collect_context(self, analysis: Dict) -> List[Dict]:
        """
        Collect context based on the provided analysis.
        """
        lang = analysis.get('language', 'c').lower()
        result = self._process_context(lang, analysis.get('required_context', {}))
        return result

    def execute_tool(self, tool_type: str, sub_tool: str, params: Dict, joern: bool = True) -> Any:
        max_retries = 3
        retry_delay = 1 
        
        for attempt in range(max_retries):
            try:
                if joern:
                    tool = self.Ltools.get_joern_tool(tool_type).get(sub_tool)
                else:
                    tool = self.Ltools.get_tree_sitter_tool(tool_type, sub_tool)
            
                if not callable(tool):
                    raise ValueError(f"{tool_type}.{sub_tool} is not callable")
                return tool(**params)
            except Exception as e:
                # if joern and self._should_restart_joern(e):
                #     self._restart_joern_container()
                #     if not self._wait_for_joern():
                #         logger.error("Failed to restart Joern container.")
                #         while True:
                #             time.sleep(10)
                #             logger.info(f"[Joern Server Error] {self.base_url}")
                #     else:
                #         self._init_project(self.project_dir)
                #         logger.info("Joern container restarted successfully.")
                logger.warning(f"[Tools Execut Attempt {attempt + 1}/{max_retries} ERROR] {tool_type}.{sub_tool}.{params}\ndetails:\n{self.project_dir}\n{self.pro_id}\n{str(e)}\n")
                if attempt < max_retries - 1: 
                    time.sleep(retry_delay)
                    continue
                logger.error(f"[Tools Execut FINAL ERROR after {max_retries} attempts] {tool_type}.{sub_tool}.{params}\ndetails:\n{self.project_dir}\n{self.pro_id}\n{str(e)}\n")
                return None

    def _in_file_cache_fetch(self, file_path: str) -> Optional[str]:
        """
        Fetch the actual file path from the cache using fuzzy matching.
        Supports wildcard-style paths like 'core/iwasm/interpreter/*' or 'tcpdump/*.c'.
        """
        if self.file_cache is None:
            return None

        target_path = file_path.strip().lstrip('/')

        # === Case: directory + wildcard extension (e.g., tcpdump/*.c) ===
        if '*' in target_path:
            if target_path.endswith('*.c') or target_path.endswith('*.h') or '*.' in target_path:
                dir_part, _, ext_pattern = target_path.partition('*')
                ext_suffix = ext_pattern if ext_pattern.startswith('.') else f'.{ext_pattern}'
                for cached_file in self.file_cache:
                    if dir_part in cached_file and cached_file.endswith(ext_suffix):
                        return cached_file

            # Fallback: match directory patterns like core/iwasm/interpreter/*
            dir_prefix = target_path.replace('*', '')
            for cached_file in self.file_cache:
                if dir_prefix in cached_file:
                    return cached_file

            logger.warning(f"No wildcard match found for: {file_path}")
            return None

        # === Case: normal fuzzy match ===
        for cached_file in self.file_cache:
            if cached_file.endswith(target_path) or target_path in cached_file:
                return cached_file

        logger.warning(f"No matching file found in cache for: \n{self.project_dir}\n{file_path}")
        return None

    def _init_project(self, project_dir: str):
        """
        Initialize the Joern project and populate file cache.
        """
        try:
            self.pro_id = self.Ltools.init_Joern_project(project_dir)
            if self.pro_id is None:
                raise RuntimeError(f"Failed to initialize Joern project: {project_dir}")
        except Exception as e:
            logger.error(f"[Tools ERROR] Failed to initialize Joern project: {str(e)}")
            raise RuntimeError(f"Failed to initialize Joern project: {str(e)}")

    def _should_restart_joern(self, exception: Exception) -> bool:
        error_msg = str(exception).lower()
        return any(msg in error_msg for msg in ["object is not iterable", "connection refused"])

    def _restart_joern_container(self):
        parsed_url = urlparse(self.base_url)
        host_port = parsed_url.port 
        
        find_cmd = f"podman ps --filter publish={host_port} --format '{{{{.ID}}}}'"
        try:
            result = subprocess.run(find_cmd, shell=True, check=True, capture_output=True, text=True)
            for cid in result.stdout.strip().split():
                subprocess.run(f"podman stop {cid}", shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logger.warning(f"[PODMAN ERROR] {e}")

        start_cmd = f"""
        podman run --rm -d \
            -p {host_port}:2000 \
            -v {host_work}:/workspace \
            -v {host_app}:/app:rw \
            -w /app \
            -t ghcr.io/joernio/joern:nightly \
            joern --server --server-host 0.0.0.0 --server-port 2000
        """
        subprocess.run(start_cmd, shell=True, check=True)

    def _wait_for_joern(self, timeout=30) -> bool:
        parsed_url = urlparse(self.baseurl)
        host, port = parsed_url.hostname, parsed_url.port
        start = time.time()
        while time.time() - start < timeout:
            try:
                with socket.create_connection((host, port), timeout=2):
                    return True
            except (ConnectionRefusedError, socket.timeout):
                time.sleep(1)
        return False

    def _process_context(self, lang: str, required_context: str, retry_count: int = 0) -> List[Dict]:
        """
        Process the required context and execute tools to gather results.
        Retries up to 3 times with fallback prompts if no valid context is collected.
        """
        if retry_count >= 3:
            logger.error("Maximum Tools retry attempts reached.")
            return [{
                "status": "context error",
                "message": "no valid result, maybe the required_context is not true.",
            }]

        try:
            actor = LLMActor(api_config=self.api_config, prompt_version=self.prompt_version)
            tools_query = actor.generate_tools_query(required_context)
            logger.info(f"Tools query: {tools_query}")
            ### repair
            if (isinstance(tools_query, list) and len(tools_query) == 1 and isinstance(tools_query[0], dict) and "tools" in tools_query[0] and isinstance(tools_query[0]["tools"], list)):
                tools_query = tools_query[0]["tools"]
           
            tools_result = []
            context_collected = False

            tools_num = 1
            for tool_entry in tools_query:
                tools_num += 1
                if tools_num % 10 == 0:
                    self.Ltools.check_joern()

                result = self._process_single_tool(tool_entry)
               
                if result["result"]:
                    tools_result.append(result)
                    context_collected = True
                    continue
                else:
                    result["result"] = "no valid result"

                # if no valid result, try fallback
                fallback_entry = self._try_tool_fallback(tool_entry)
                if fallback_entry:
                    fallback_result = self._process_single_tool(fallback_entry)
                    if fallback_result["result"]:
                        context_collected = True
                    else:
                        fallback_result["result"] = "no valid result, and fuzzy match failed"
                    tools_result.append(fallback_result)
                else:
                    tools_result.append(result)
                   
            if context_collected:
                return tools_result

            # Retry with updated context prompt
            updated_context = (
                f"{required_context}\nThe last tools query returned no valid results: {tools_query}.\n"
                "Maybe the file_path or func_name is incorrect. Please regenerate tool parameters accordingly."
            )
            return self._process_context(lang, updated_context, retry_count + 1)

        except Exception as e:
            logger.error(f"Error processing context: {str(e)}")
            return [{
                "status": "context error",
                "message": str(e),
                "timestamp": datetime.now().isoformat()
            }]

    def _process_single_tool(self, tool_entry: Dict) -> Dict:
        tool_name = tool_entry.get("tool")
        tool_params = tool_entry.get("params", {})

        if tool_name == 'query':
            tool_name = 'query.query'
        if not tool_name or '.' not in tool_name:
            logger.warning(f"Invalid tool format: {tool_entry}")
            return {"tool": tool_name, "result": None}

        tool_type, sub_tool = tool_name.split('.')
        parsed_params = self._prepare_tool_params(tool_type, tool_params)
        tool_result = self.execute_tool(tool_type, sub_tool, parsed_params)
        if tool_result == "Query timed out":
            logger.warning(f"Tool execution timed out: {tool_name}({parsed_params}), retrying...")
            if self.Ltools.check_joern():
                tool_result = self.execute_tool(tool_type, sub_tool, parsed_params)
                if tool_result == "Query timed out":
                    logger.error(f"Tool execution still timed out: {tool_name}({parsed_params})")
                    return {"tool": tool_name, "result": "no valid result, Query timed out"}
        print(f"Tool result: {tool_result}")
        formatted_result = self._format_tool_result(tool_type, tool_result)
        logger.info(f"Executing tool: {tool_type}.{sub_tool}({parsed_params})")
        logger.info(f"Tool result: {formatted_result}")
        return {
            "tool": f"{tool_type}.{sub_tool}({parsed_params})",
            "result": formatted_result
        }

    def _prepare_tool_params(self, tool_type: str, params: Dict) -> Dict:
        parsed = {}
        for key, val in params.items():
            parsed[key] = val
            if key == "file_path":
                val = self._in_file_cache_fetch(val) or val
            if key == "value":
                if "struct " in val:
                    val = val.split("struct ")[-1]
                parsed["value_name"] = val
                del parsed[key]
            if key == "value_name":
                if "struct " in val:
                    val = val.split("struct ")[-1]
                parsed["value_name"] = val
            if key == "func_name" and "::" in val:
                val = val.split("::")[-1]
                parsed["func_name"] = val
            if key == "end_line" and int(val) == -1:
                parsed["end_line"] = 20
            if "query" in key:
                del parsed[key]
                parsed["query_string"] = val
                
        if "caller" in tool_type:
            tool_type = "caller_info"
        elif "func" in tool_type:
            tool_type = "func_info"
        elif "value" in tool_type:
            tool_type = "value_info"
        if tool_type in {"func_info", "caller_info", "code_info"}:
            parsed["project_dir"] = self.project_dir
        return parsed
   
    # fuzzy match
    def _try_tool_fallback(self, tool_entry: Dict) -> Optional[Dict]:
        tool = tool_entry["tool"]
        params = tool_entry["params"]

        fallback_map = {
            "func_info.fetch_func_by_file_name": ("func_info.fetch_func_by_name", ["func_name"]),
            "caller_info.find_caller_for_func_file": ("caller_info.find_caller_for_func", ["func_name"]),
            "value_info.fetch_member_or_value_by_file_name": ("func_info.fetch_func_by_name", ["value_name"]), # maybe a value, but a function
        }

        if tool in fallback_map:
            fallback_tool, required_keys = fallback_map[tool]
            new_params = {k: v for k, v in params.items() if k in required_keys}
            if new_params:
                return {"tool": fallback_tool, "params": new_params}

        return None

    def _format_tool_result(self, tool_type: str, tool_result: Any) -> Any:
        """
        Format the result of a tool based on its type.
        """
        try:
            if tool_type == "func_info":
                if not tool_result:
                    return None
                if isinstance(tool_result, list):
                    return [
                        {
                            "type": "function_def",
                            "code": item["_2"],
                            "start_line": item["_3"],
                            "end_line": item["_4"],
                            "full_name": item["_5"],
                            "file_path": item["_6"]
                        }
                        for item in tool_result[:3]
                    ]
               
            elif tool_type == 'caller_info':
                if not tool_result:
                    return "no valid result, it may be a leaf function"

                if not isinstance(tool_result, list):
                    logger.warning(f"Unexpected return type for caller_info: {type(tool_result)}")
                    return []
                return [
                    {
                        "type": "caller_info",
                        "call_line": item.get("call_line", -1),
                        "call_code": item.get("call_code", ""),
                        "caller_code": item.get("caller_func", ""),
                        "caller_start": item.get("caller_start", -1),
                        "file_path": item.get("call_path", "")
                    }
                    for item in tool_result[:10]
                ]
            elif tool_type == 'value_info':
                if isinstance(tool_result, dict) and "matches" in tool_result:
                    unique_matches = {}
                    for m in tool_result["matches"]:
                        key = (m[1], m[2])  # key is (line, func_name)
                        if key not in unique_matches or len(m[0]) > len(unique_matches[key][0]):
                            unique_matches[key] = m
                    formatted_matches = [
                        {
                            "full_code": m[0],
                            "line": m[1],
                            "func_name": m[2]
                        }
                        for m in unique_matches.values()
                    ]
                    if not formatted_matches and tool_result.get("struct_type") is None:
                        return "no valid result, please check the value name"
                    return {
                        "type": "value_info",
                        "value_trace": formatted_matches[:10],
                        "struct_var": tool_result.get("struct_var"),
                        "struct_type": tool_result.get("struct_type"),
                        "struct_definition": tool_result.get("struct_definition")
                    }

            elif tool_type == 'query_info':
                FILTER_KEYS = {
                    "_id", "_label", "astParentType", "astParentFullName",
                    "order", "genericSignature", "dynamicTypeHintFullName",
                    "possibleTypes", "isExternal"
                }
                if isinstance(tool_result, list):
                    if all(isinstance(item, dict) for item in tool_result):
                        cleaned = [
                            {k: v for k, v in item.items() if k not in FILTER_KEYS}
                            for item in tool_result
                        ]
                        return cleaned
                    elif all(isinstance(item, str) for item in tool_result):
                        return tool_result[:10]  # limit 10
                    else:
                        return tool_result  # fallback, unknown type
                elif isinstance(tool_result, dict):
                    return {k: v for k, v in tool_result.items() if k not in FILTER_KEYS}
                else: # fallback for str, int, etc.
                    return tool_result
            else:
                return tool_result  
        except Exception as e:
            logger.error(f"Error formatting tool result: {str(e)} \n{tool_result}")
            return []

class VulnWorkflow:
    """Orchestrates vulnerability analysis workflow with state management

    Attributes:
        MAX_ITERATIONS: Maximum allowed analysis cycles
        CONFIDENCE_THRESHOLD: Minimum confidence score for finalization
    """

    MAX_ITERATIONS = 8
    CONFIDENCE_THRESHOLD = 0.60

    def __init__(self, api_config: Dict = None):
        self.api_config = api_config or {}
        self.graph = self._build_workflow_graph()

    def _build_workflow_graph(self) -> StateGraph:
        """Builds the StateGraph for the vulnerability analysis workflow."""
        builder = StateGraph(AgentState)

        # Define nodes
        builder.add_node("initialize", self._initialize_analysis)
        builder.add_node("collect", self._collect_context)
        builder.add_node("analyze", self._perform_analysis)
        builder.add_node("finalize", self._generate_report)
        builder.add_node("error_handler", self._handle_final_error) # Add an error handler node

        # Define entry point
        builder.set_entry_point("initialize")

        builder.add_conditional_edges(
            "initialize",
            self._route_from_initialize,
            {
                "collect": "collect",
                "analyze": "analyze", 
                "finalize": "finalize",
                "error_handler": "error_handler"
            }
        )

        # collect transitions always to analyze, unless there's an error during collection itself
        builder.add_conditional_edges(
            "collect",
            self._route_from_collect,
            {
                "analyze": "analyze",
                "error_handler": "error_handler" 
            }
        )

        # analyze transitions based on need_context, confidence, iteration limit, or errors
        builder.add_conditional_edges(
            "analyze",
            self._route_from_analyze,
            {
                "collect": "collect",
                "finalize": "finalize",
                "error_handler": "error_handler" 
            }
        )

        return builder.compile()

    # --- Workflow Nodes ---
    def _initialize_analysis(self, state: AgentState) -> Dict:
        """Initial analysis phase. Validates input and performs first pass."""
        # Input Validation
        required_keys = ["patch", "description", "msg"]
        if not all(key in state for key in required_keys):
            missing = [key for key in required_keys if key not in state]
            error_msg = f"Missing required initial state keys: {', '.join(missing)}"
            logger.error(error_msg)
            return self._update_state_with_error(state, error_msg)

        try:
            critic = VulnerabilityCritic(self.api_config, prompt_version=state.get("prompt_version", "default"))
            initial, prompt = critic.analyze_initial({
                "patch": state["patch"],
                "description": state["description"],
                "msg": state["msg"],
            })

            need_context = initial.get("need_context", False)
            if isinstance(need_context, str):
                 need_context = need_context.lower() == 'true'
            confidence_score = initial.get("confidence_score", 0.0)

            new_state = {
                **state,
                "iteration": 0, # Initialize iteration count
                "enriched_data": state.get("enriched_data", []), # Ensure enriched_data exists
                "analysis": {
                    "patch": state["patch"], 
                    "msg": state["msg"],
                    "description": state["description"],
                    "language": initial.get("language", ""),
                    "vulnerability_type": initial.get("vulnerability_type", ""),
                    "repair_strategy": initial.get("repair_strategy", ""),
                    "need_context": need_context, 
                    "required_context": initial.get("required_context", {}),
                    "confidence_score": confidence_score,
                    "root_cause": initial.get("root_cause", "") # May have partial root cause initially
                },
                "history": state.get("history", []) + [{
                    "stage": "initial",
                    "prompt": prompt,
                    "result": initial,
                    "timestamp": datetime.now().isoformat()
                }]
            }
            new_state["need_context"] = need_context
            new_state["confidence_score"] = confidence_score
            new_state["root_cause"] = initial.get("root_cause", "")


            return new_state

        except Exception as e:
            error_msg = f"Initial analysis failed: {str(e)}"
            logger.error(error_msg, exc_info=True) # Log traceback
            return self._update_state_with_error(state, error_msg)


    def _collect_context(self, state: AgentState) -> Dict:
        """Collects additional context based on analysis requirements."""
        if state.get("status") == "error":
             return state 

        try:
            required_actor_keys = ["project_dir", "joern", "file_cache", "base_url"]
            if not all(key in state for key in required_actor_keys):
                 missing = [key for key in required_actor_keys if key not in state]
                 error_msg = f"Missing required actor configuration in state: {', '.join(missing)}"
                 logger.error(error_msg)
                 return self._update_state_with_error(state, error_msg)

            actor = ContextActor(state["project_dir"], self.api_config, state['joern'], state['file_cache'], state["base_url"], state["prompt_version"])
            state['joern'] = 1
            required_context_info = state.get("analysis", {}).get("required_context", {})
            if not required_context_info:
                 logger.info("Analysis requires no additional context collection.")
                 return state

            collected = actor.collect_context(state["analysis"])

            successful_collections = [item for item in collected if item.get("status") != "context error"]
            error_collections = [item for item in collected if item.get("status") == "context error"]
            if error_collections:
                 logger.warning(f"Encountered {len(error_collections)} items with context collection errors.")

            updated_enriched_data = state.get("enriched_data", []) + successful_collections

            new_state = {
                **state,
                "enriched_data": updated_enriched_data,
                "history": state.get("history", []) + [{
                    "stage": "collection",
                    "required_context": required_context_info,
                    "results": collected, 
                    "timestamp": datetime.now().isoformat()
                }],
                "debug_trace": state.get("debug_trace", []) + [
                    f"Collected {len(successful_collections)} context items. ({len(error_collections)} failed)"
                ]
            }

            return new_state

        except KeyError as e:
            error_msg = f"Missing required state key for context collection: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return self._update_state_with_error(state, error_msg)
        except Exception as e:
            error_msg = f"Context collection failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return self._update_state_with_error(state, error_msg)


    def _perform_analysis(self, state: AgentState) -> Dict:
        """Performs root cause analysis using collected context."""
        if state.get("status") == "error":
             return state 

        current_iteration = state.get("iteration", 0)
        new_iteration = current_iteration + 1
        state["iteration"] = new_iteration 

        try:
            critic = VulnerabilityCritic(self.api_config, prompt_version=state.get("prompt_version", "default"))
            report, prompt = critic.determine_root_cause(state)
            if report.get("status") == "error":
                error_msg = f"Analysis failed: {report.get('reason', 'Unknown error')}"
                logger.error(error_msg, exc_info=True)
                return self._update_state_with_error(state, error_msg)
            need_context = report.get("need_context", False)
            if isinstance(need_context, str):
                 need_context = need_context.lower() == 'true'

            confidence_score = report.get("confidence_score", 0.0)

            new_state = {
                **state, #
                "analysis": {**state.get("analysis", {}), **report}, 
                "need_context": need_context, 
                "confidence_score": confidence_score, 
                "root_cause": report.get("root_cause", state.get("root_cause", "")), # Update root cause
                "history": state.get("history", []) + [{
                    "stage": "analysis",
                    "iteration": new_iteration,
                    "prompt": prompt,
                    "result": report,
                    "timestamp": datetime.now().isoformat()
                }],
                 "debug_trace": state.get("debug_trace", []) + [
                    f"Performed analysis iteration {new_iteration}. Needs more context: {need_context}. Confidence: {confidence_score:.2f}"
                 ]
            }

            return new_state

        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return self._update_state_with_error(state, error_msg)


    def _generate_report(self, state: AgentState) -> Dict:
        """Generates the final vulnerability report."""
        if state.get("status") == "error":
             logger.warning("Attempted to generate report while in error state.")
             return {
                    **state,
                    "status": "error",
                    "final_report": "Error state reached before report generation.",
                    "debug_trace": state.get("debug_trace", []) + ["Report generation failed due to error state."]
             }

        logger.info("Finalizing report.")
        final_report_content = f"""
Vulnerability Report
====================

Status: Completed
Root Cause: {state.get('root_cause', 'N/A')}
Confidence Score: {state.get('confidence_score', 0.0):.2f}
Vulnerability Type: {state.get('analysis', {}).get('vulnerability_type', 'N/A')}
Repair Strategy: {state.get('analysis', {}).get('repair_strategy', 'N/A')}
"""
        for entry in state.get("history", []):
             final_report_content += f"- Stage: {entry['stage']}, Timestamp: {entry['timestamp']}\n"
             if entry['stage'] == 'analysis':
                  final_report_content += f"  Iteration: {entry.get('iteration', 'N/A')}, Needs Context: {entry['result'].get('need_context', 'N/A')}, Confidence: {entry['result'].get('confidence_score', 'N/A'):.2f}\n"
             # Add more details from history entries as needed

        return {
            **state,
            "status": "completed",
            "final_report": final_report_content,
            "debug_trace": state.get("debug_trace", []) + ["Report generation completed."]
        }

    def _handle_final_error(self, state: AgentState) -> Dict:
        """Handles the workflow reaching a final error state."""
        error_message = state.get("error", "An unknown error occurred.")
        logger.error(f"Workflow ended in error state: {error_message}")

        return {
            **state,
            "status": "error",
            "final_report": f"Workflow failed: {error_message}\nDebug Trace:\n" + "\n".join(state.get("debug_trace", []))
        }

    # --- Conditional Routing Functions ---
    def _route_from_initialize(self, state: AgentState) -> str:
        """Routes from initialize based on initial analysis and errors."""
        if state.get("status") == "error":
            logger.debug("_route_from_initialize: Routing to error_handler due to error status.")
            return "error_handler"

        need_context = state.get("need_context", False)
        if isinstance(need_context, str):
            need_context = need_context.lower() == 'true'
        confidence_score = state.get("confidence_score", 0.0)

        logger.debug(f"_route_from_initialize: Need context: {need_context}, Confidence: {confidence_score:.2f}")

        if need_context:
            logger.debug("_route_from_initialize: Routing to collect.")
            return "collect"
        else:
            if confidence_score >= self.CONFIDENCE_THRESHOLD:
                logger.debug("_route_from_initialize: Routing to finalize (confident enough).")
                return "finalize"
            else:
                logger.debug("_route_from_initialize: Routing to analyze (no context needed, but not confident).")
                return "analyze" 

    def _route_from_collect(self, state: AgentState) -> str:
        """Routes from collect based on collection success/failure."""
        # Check for error state first. Collection errors set status="error".
        if state.get("status") == "error":
            logger.debug("_route_from_collect: Routing to error_handler due to error status.")
            return "error_handler"

        logger.debug("_route_from_collect: Routing to analyze.")
        return "analyze"


    def _route_from_analyze(self, state: AgentState) -> str:
        """Routes from analyze based on analysis results, iteration limit, and errors."""
        if state.get("status") == "error":
            logger.debug("_route_from_analyze: Routing to error_handler due to error status.")
            return "error_handler"

        current_iteration = state.get("iteration", 0) # Should be >= 1 after analysis
        need_context = state.get("need_context", False) 
        if isinstance(need_context, str):
            need_context = need_context.lower() == 'true'
        confidence_score = state.get("confidence_score", 0.0)

        logger.debug(f"_route_from_analyze: Iteration: {current_iteration}, Need context: {need_context}, Confidence: {confidence_score:.2f}")

        # Check iteration limit
        if current_iteration >= self.MAX_ITERATIONS:
            logger.warning(f"_route_from_analyze: Maximum iterations ({self.MAX_ITERATIONS}) reached.")
            logger.debug("_route_from_analyze: Routing to finalize (max iterations reached).")
            return "finalize"

        if need_context:
            # logger.debug("_route_from_analyze: Routing to collect (needs more context).")
            return "collect"
        else:
            if confidence_score >= self.CONFIDENCE_THRESHOLD:
                logger.debug("_route_from_analyze: Routing to finalize (confident enough).")
                return "finalize"
            else:
                error_msg = f"Analysis finished (no context needed) but confidence ({confidence_score:.2f}) below threshold ({self.CONFIDENCE_THRESHOLD})."
                logger.error(error_msg)
                state = self._update_state_with_error(state, error_msg)
                return "error_handler"


    # --- Helper Method for Error State Update ---
    def _update_state_with_error(self, state: AgentState, message: str) -> Dict:
        """Helper to consistently update state when an error occurs."""
        if state is None:
            state = {}

        debug_trace = state.get("debug_trace", [])
        if not debug_trace or debug_trace[-1] != message: 
             debug_trace.append(message)

        return {
            **state,
            "status": "error",
            "error": message,
            "debug_trace": debug_trace
        }


    # --- Utility Method ---
    def visualize_workflow(self) -> str:
        """Provides a visual representation of the workflow."""
        return """
        My Vulnerability Analysis Workflow (Revised)
        ===========================================
        Nodes:
        - initialize: Initial vulnerability assessment & input validation
        - collect: Context data collection
        - analyze: Root cause analysis (iterative)
        - finalize: Report generation (success state)
        - error_handler: Handles workflow errors (failure state)

        State Transitions:
        [initialize] --(needs context)--> [collect]
        [initialize] --(no context, confident)--> [finalize]
        [initialize] --(no context, not confident)--> [analyze]
        [initialize] --(initial error)--> [error_handler]

        [collect] --(successful)--> [analyze]
        [collect] --(collection error)--> [error_handler]

        [analyze] --(needs more context)--> [collect]
        [analyze] --(no more context, confident)--> [finalize]
        [analyze] --(no more context, not confident OR max iterations reached)--> [finalize] # Refined logic: finalize on max iter regardless of confidence
        [analyze] --(analysis error OR stuck)--> [error_handler]
        [analyze] --(max iterations, still needs context)--> [finalize] # Max iter implies finalizing state

        Error Flow: Any node can potentially lead to [error_handler] if a critical exception or defined error condition occurs.
        Final States: [finalize], [error_handler]
        """


def main():
    config = {
        "model": "Qwen/Qwen3-32B",
        # "model": "deepseek-ai/DeepSeek-V3",
        # "model": "gpt-4o-2024-11-20",
        "temperature": 0.6,
        "api_key": os.getenv("OPENAI_API_KEY"),
        "base_url": os.getenv("OPENAI_API_BASE")
    }
    # Initialize workflow
    workflow = VulnWorkflow(config)
   
    # Validate environment configuration
    if not config["api_key"] or not config["base_url"]:
        print("Error: Missing required API configuration")
        return

    print("Workflow Visualization:")
    print(workflow.visualize_workflow())

    with open(precess_info, 'r', encoding='utf-8') as f:
        vul_info = json.load(f)
   
    msg = vul_info[0]["commit_msg"]
    description = vul_info[0]["description"]
    project_dir = vul_info[0]["raw_repo"]
    file_cache = vul_info[0]["before_cpg_file_cache"]
    cpg_file = vul_info[0]["before_cpg_file"]
    patch_with_file = []
    for patch in vul_info[1:]:
        patch_with_file.append({
            "func_name": patch["func_name"],
            # "func_before": patch["func_before"],
            "patch": patch["patch"],
            "file_path": patch["file_path"],
        })
    # Prepare initial state with complete required fields
    initial_state = AgentState(
        project_dir=project_dir,
        patch=patch_with_file,
        description=description,
        msg=msg,
        joern=0,
        file_cache=file_cache,
        cpg_file=cpg_file,
        base_url="http://localhost:2000",
        prompt_version="default",
        enriched_data=[],
        analysis={},
        root_cause="",
        confidence_score=0.0,
        iteration=0,
        need_context=True,
        history=[],
        debug_trace=[],
        status=None,
        error=None
    )
    try:
        result = workflow.graph.invoke(initial_state)
        if result.get("status") == "completed":
            analysis = result.get("analysis")
            need_context = analysis.get("need_context")
        else:
            error_msg = result.get("error")
            if error_msg:
                print(f"Error: {error_msg}")

        save_result_to_json =""
        logger.info(f"has saved result")
    except Exception as e:
        logger.error(f"Workflow execution failed: {str(e)}")

if __name__ == "__main__":
    main()