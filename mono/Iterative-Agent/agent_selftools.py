from pathlib import Path
from typing import Dict, Callable
import hashlib
import shutil
import time
import os
import sys
import filecmp

from logging_helper import global_logger
from tree_sitter_tools.java_utils import java_analyzer_context,java_find_call_init_in_project,java_find_func_call_info_in_project
from tree_sitter_tools.cpp_utils import cpp_analyzer_context,cpp_find_call_init_in_project,cpp_find_func_call_info_in_project
from tree_sitter_tools.c_utils import c_analyzer_context,c_find_call_init_in_project,c_find_func_call_info_in_project
from joern_tools.joern_service import JoernQueryService
from joern_tools.server_tools import JoernService

out_workspace = "/joern_tools/app/workspace"
out_cache = "/joern_tools/app/cache"

out_root_ = "/joern_tools/app/repos/"
in_root_ = "/app/repos/"

class LangTools: 
    def __init__(self, base_url: str = "http://127.0.0.1:2000"):
        self.jq = JoernService(out_workspace=out_workspace, out_cache=out_cache, base_url=base_url)  # default port: 2000
        self.JQ = JoernQueryService(self.jq)
        self._TOOL_MAP = {
            ####### if you need more tools, please add them here #######
            # 1. add the tool API
            # 2. easily add the request API in execute_tool() in agent_worker.py function
            # 3. other params or format you want by yourself, if you do not, the raw result will be returned
            # tree_sitter is a eaxmple, you can add more tools here
            "tree_sitter": {
                "c": {
                    "analyzer": c_analyzer_context,
                    "find_init": c_find_call_init_in_project,
                    "find_calls": c_find_func_call_info_in_project
                },
                "cpp": {
                    "analyzer": cpp_analyzer_context,
                    "find_init": cpp_find_call_init_in_project,
                    "find_calls": cpp_find_func_call_info_in_project
                },
                "java": {
                    "analyzer": java_analyzer_context,
                    "find_init": java_find_call_init_in_project,
                    "find_calls": java_find_func_call_info_in_project
                }
            },
            "joern": {
                "project_init": self.jq.init_project,  # project_dir
                "close_project": self.jq.close_project,  # project_name
                "file_info": {
                    "get_allfile_by_cpg": self.JQ.func.get_allfile_by_cpg,  # none
                    "fetch_allfunc_by_file": self.JQ.func.fetch_allfunc_by_file,  # file_path
                },
                "func_info": {
                    "fetch_func_by_file_name": self.JQ.func.fetch_func_by_file_name,  # file_path, func_name, poject_dir
                    "fetch_func_by_file_and_line": self.JQ.func.fetch_func_by_file_and_line,  # file_path, one_line, poject_dir
                    "fetch_func_by_file_lines": self.JQ.func.fetch_func_by_file_lines,  # file_path, start_line, end_line, poject_dir
                    "fetch_func_by_name": self.JQ.func.fetch_func_by_name,  # func_name (fuzzy search), poject_dir
                },
                "value_info": { 
                    "fetch_member_or_value_by_file_name": self.JQ.var.fetch_member_or_value_by_file_name,  # value_name, file_path
                    "fetch_member_or_value_by_name": self.JQ.var.fetch_member_or_value_by_file_name,  # value_name (fuzzy search)
                    "get_item_by_id": self.JQ.var.get_item_by_id,  # item_type, item_id
                    "fetch_id_by_valuename_line": self.JQ.var.fetch_id_by_valuename_line,  # file, value, line
                },
                "code_info": {
                    "fetch_code_by_file_lines": self.JQ.code.fetch_file_code_by_lines,  # project_dir, file_path,  start_line, end_line
                },
                "caller_info": {
                    # caller_info.find_caller_for_func_file
                    "find_caller_for_func": self.JQ.caller.find_caller_info_for_func,  #  func_name, poject_dir
                    "find_caller_for_func_file": self.JQ.caller.find_caller_info_for_func, # file_path, func_name, poject_dir
                    "get_caller_chain_for_func": self.JQ.caller.get_caller_chain_for_func,  #  file_path, func_name, max_depth: int = 1, poject_dir
                    "java_find_references_for_file": self.JQ.caller.java_find_references_for_file,  # file_path
                    "c_find_references_for_file": self.JQ.caller.c_find_references_for_file,  # file_path
                },
                "callee_info": {
                    "fetch_callees_by_file_func": self.JQ.func.fetch_func_by_file_name,  # file_path, func_name, poject_dir
                    "fetch_callees_by_file_func_line": self.JQ.callee.fetch_callees_by_file_func_line,  # file_path, func_name, line
                },
                "dependency_info": {
                    "get_ids_by_funclist": self.JQ.dependency.get_ids_by_funclist,  # func_list
                    "generate_pdg_for_method": self.JQ.dependency.generate_pdg_for_method,  # func_id_list
                    "save_all_nodes": self.JQ.dependency.save_all_nodes,  # save_path (in Joern Docker)
                },
                "query_info": {
                    "query": self.JQ.query.query,  # query_str
                },
            }
        }

    def _get_tool(self, tool_type: str, sub_tool: str = None) -> Callable:
        """Retrieve tool with validation"""
        tool_type = tool_type.lower()
        if tool_type not in self._TOOL_MAP:
            raise ValueError(f"Unsupported tool type: {tool_type}")
        
        if sub_tool is None:
            return self._TOOL_MAP[tool_type]
        
        if sub_tool not in self._TOOL_MAP[tool_type]:
            raise ValueError(f"Invalid sub-tool: {sub_tool} for {tool_type}")
        
        return self._TOOL_MAP[tool_type][sub_tool]
    
    def get_joern_tool(self, sub_tool: str) -> Callable:
        """Retrieve Joern-specific tool"""
        return self._get_tool("joern", sub_tool)
    
    def get_tree_sitter_tool(self, lang: str, sub_tool: str) -> Callable:
        """Retrieve Tree-sitter-specific tool"""
        lang = lang.lower()
        if lang not in self._TOOL_MAP["tree_sitter"]:
            raise ValueError(f"Unsupported language: {lang}")
        
        return self._get_tool("tree_sitter", lang)[sub_tool]

    def supported_operations(self) -> Dict:
        return {
            lang: list(tools.keys()) 
            for lang, tools in self._TOOL_MAP.items()
        }


    def check_joern(self) -> bool:
        retry_count = 0
        while True:
            res = self.jq._query("help")
            if "help.<command>" in res:
                return True
            else:
                retry_count += 1
                time.sleep(retry_count)
                if retry_count > 20:
                    global_logger.error(f"{self.jq.base_url} Joern service is not running, please check the service.")
                    time.sleep(100)
                
    def init_Joern_project(self, project_dir: str) -> str:
        # print(f"Project path: {project_dir}")
        while True:
            res = self.jq._query("close")
            if "No CPG" in res:
                global_logger.info(f"{self.jq.base_url} init new project")
                res = self.jq._query("close")
                time.sleep(2)
                break
            else:
                # global_logger.warning(f"{self.jq.base_url} service is checking, retrying...")
                time.sleep(2)

        project_name = os.path.basename(project_dir)
        joern_hash = hashlib.md5(f"{in_root_}{project_name}".encode()).hexdigest()
        joern_workspace_cpg_path = Path(out_workspace) / joern_hash / "cpg.bin"
        precomputed_cpg_path = Path(project_dir).parent.parent / "Joern_files" / "cpgs" / "cpg.bin"

        precomputed_cpg_path_bak = Path(project_dir).parent.parent / "Joern_file" / "cpgs" / "cpg.bin"
        if precomputed_cpg_path_bak.exists():
            precomputed_cpg_path = precomputed_cpg_path_bak
            
        if not precomputed_cpg_path.exists():
            global_logger.error(f"[CPG not found] Missing expected precomputed CPG: {precomputed_cpg_path}")
            raise FileNotFoundError(f"Missing expected precomputed CPG: {precomputed_cpg_path}")

        if joern_workspace_cpg_path.exists(): 
            # cpg2workspace
            if not filecmp.cmp(precomputed_cpg_path, joern_workspace_cpg_path, shallow=False):
                global_logger.info(f"[CPG Update] {precomputed_cpg_path} -> {joern_workspace_cpg_path}")
                shutil.copy2(precomputed_cpg_path, joern_workspace_cpg_path)
                # global_logger.info("Workspace CPG already matches precomputed one")
            pro_id = self.jq.init_project(f"{in_root_}{project_name}")
        else:
            # cpg2_in_root
            global_logger.info(f"[CPG Copy] {precomputed_cpg_path} -> {out_root_}{project_name}")
            out2in_cpg_path = Path(out_root_) / project_name / "cpg.bin"
            # print(f"Copying CPG to {out2in_cpg_path}")
            if not out2in_cpg_path.exists() or out2in_cpg_path.stat().st_size == 0:
                global_logger.info(f"[CPG Copy] {precomputed_cpg_path} -> {out2in_cpg_path}")
                os.makedirs(out2in_cpg_path.parent, exist_ok=True)
                shutil.copy2(precomputed_cpg_path, out2in_cpg_path)
            pro_id = self.jq.import_cpg(f"{out_root_}{project_name}")

        if pro_id == "0 nodes":
            global_logger.error("[CPG 0node] Failed to initialize Joern project")
            return None
        if pro_id == "error":
            global_logger.error("[CPG Error] Failed to initialize Joern project")
            return None
        return pro_id




    

         
logger = global_logger
def test_joern_tools():
    logger.info("=== Starting Joern Tools Test ===")
    jq = JoernService(out_workspace=out_workspace, out_cache=out_cache, base_url="http://localhost:2000")
    lang_tools = LangTools(base_url="http://localhost:2008")

    test_project_dir = "/app/test/test_1"  # inside Docker path
    pro_id = jq.init_project(test_project_dir)
    assert pro_id is not None, "Project initialization failed"

    logger.info("Joern project initialized successfully.")

    # Get all files
    file_info_tool = lang_tools.get_joern_tool("file_info")["get_allfile_by_cpg"]
    files = file_info_tool()
    assert isinstance(files, list) and files, "No files found in CPG"
    logger.info(f"Files in CPG: {files}")

    # Test one file
    test_file = files[0]  # pick the first available file

    # Get all functions
    all_func_tool = lang_tools.get_joern_tool("file_info")["fetch_allfunc_by_file"]
    funcs = all_func_tool(test_file)
    print(funcs)

    # Pick a function
    func_name = funcs[0]

    # Fetch function by name
    func_info_tool = lang_tools.get_joern_tool("func_info")["fetch_func_by_file_name"]
    func_info = func_info_tool(func_name=func_name, file_path=test_file, project_dir="1")
    assert func_info, f"Function '{func_name}' not found in {test_file}"
    logger.info(f"Function '{func_name}' info: {func_info}")

    # Fetch callers
    caller_tool = lang_tools.get_joern_tool("caller_info")["find_caller_for_func_file"]
    caller_info = caller_tool(file_path=test_file, func_name=func_name)
    logger.info(f"Callers of {func_name}: {caller_info}")

    query_string = "cpg.call.name(\"printf\").code.l"
    res = lang_tools.get_joern_tool("query_info")["query"](query_string)
    print(res)

    # value
    value_tool = lang_tools.get_joern_tool("value_info")["fetch_member_or_value_by_file_name"]
    value_name = 'num'
    value_info = value_tool(value_name=value_name, file_path=test_file)
    print(value_info)

if __name__ == "__main__":
    test_joern_tools()
