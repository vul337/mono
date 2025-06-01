from pathlib import Path
from tree_sitter import Parser, Language, Node
from functools import lru_cache, wraps
from typing import Dict, List, Optional, Callable, Type, Any, Union
import logging
from collections import deque, defaultdict
from dataclasses import dataclass
from func_file_utils import LanguageConfig, UniversalCodeAnalyzer, Language

@dataclass
class FunctionDefinition:
    file: str
    func_name: str
    func_params: List[str]
    start_line: int
    end_line: int
    code: str

@dataclass
class DirectCallInfo:
    isLibrary: bool                 
    definitions: List[FunctionDefinition]  
    sub_calls: List[Dict]   # [{"func_name": "foo", "params": ["1", "2"]}, ...]

@dataclass
class FunctionCallAnalysisResult:
    target_func: FunctionDefinition # {"file": "main.c", "func_name": "main", "start_line": 10, "end_line": 20, "code": "int main() {.foo(1,2)..}"}
    sub_calls: List[Dict] # [{"file_name": "foo", "line": 15, "params": ["1", "2"]}, ...]
    direct_calls: List[DirectCallInfo] # [{"isLibrary": False, "definitions": [foo `s FunctionDefinition], "sub_calls": [sub_calls in foo()]}, ...]


class ProjectAnalyzer:
    def __init__(self, config: LanguageConfig):
        self.config = config
        self.analyzer = UniversalCodeAnalyzer(config)
        self.function_index: Dict[tuple, List[FunctionDefinition]] = defaultdict(list) # func_name: [{file, start_line, end_line, code}]
        self.direct_calls: Dict[tuple, List[DirectCallInfo]] = defaultdict(list) # func_name: [caller1, caller2, ...]
         

    def build_index(self, project_dir: Path):
        extensions = {
            'c': ['.c', '.h'],
            'cpp': ['.cpp', '.hpp', '.cc', '.h'],
            'java': ['.java']
        }[self.config.name]

        
        for ext in extensions:
            for file_path in project_dir.glob(f'**/*{ext}'):
                # print(file_path)
                if file_path.is_file():
                    # function_index: Dict[tuple, List[FunctionDefinition]] = defaultdict(list) - build function index
                    self._process_file(file_path)
                    # call_graph: Dict[tuple, List[DirectCallInfo]] = defaultdict(list)  - build call graph
                    self._process_call_graph(file_path)

        
        # for ext in extensions:
        #     for file_path in project_dir.glob(f'**/*{ext}'):
        #         if file_path.is_file():
        #             self._process_call_graph(file_path)


    def _process_file(self, file_path: Path):
        root = self.analyzer.parse_file(file_path)
        if not root:
            return

        functions = self.analyzer._find_functions(root, 0, float('inf'))
        for func in functions:

            definition = FunctionDefinition(
                file=str(file_path),
                func_name=func['name'],
                func_params=func['func_params'],
                start_line=func['start_line'],
                end_line=func['end_line'],
                code=func['code']
            )
            key = (str(file_path), func['name'])
            self.function_index[key].append(definition)
     
    def _process_call_graph(self, file_path: Path):
        root = self.analyzer.parse_file(file_path)
        if not root:
            return

        calls = self.analyzer._find_calls_ret_node(root, 0, float('inf')) # all calls in file
        for call in calls: 
            caller_func_node = self._find_enclosing_function(call['node']) # locate the caller function
        
            if not caller_func_node:
                continue
            
            caller_name = self.config.function_name_extractor(caller_func_node) #（file，caller） used as key
            caller_key = (str(file_path), caller_name)
            
            # direct_call info
            callee_name = call['name']
            call_line = call['line']
            call_params = call['params']
            # print(caller_name, callee_name, call_line, call_params)
            # input()

            isLibrary = False
            # match callee definition
            if callee_name in self.config.library_functions: # isLibrary: True if callee is a library function
                # name = callee_name
                callee_definitions = []
                callee_definitions.append(FunctionDefinition(file="",func_name=callee_name,func_params=[],start_line=0,end_line=0,code=""))
                isLibrary = True
            else:
                callee_definitions = self.find_matching_definitions(callee_name, call_params)
                if not callee_definitions:
                    isLibrary = True
            
            # get sub calls
            sub_calls = []
            if callee_definitions:
                for defn in callee_definitions:
                    callee_root = self.analyzer.parse_file(Path(defn.file))
                    if callee_root:
                        sub_calls.extend(self.analyzer._find_calls(callee_root, defn.start_line, defn.end_line))
            
            self.direct_calls[caller_key].append(DirectCallInfo(
                isLibrary=isLibrary,  
                definitions=callee_definitions,
                sub_calls=[{"func_name": sub_call['name'], "params": sub_call['params'], "line": sub_call['line']} for sub_call in sub_calls] if sub_calls else []
            ))

    # find caller
    def _find_enclosing_function(self, node: Node) -> Optional[Node]:

        current = node.parent
        while current:
            if current.type == self.config.node_types['function_def']:
                return current
            current = current.parent
        return None


    # def find_definition(self, func_name: str) -> List[Dict]:
    #     return self.function_index.get(func_name, [])

    # use func_name、call_param to find matching definitions 
    
    def find_matching_definitions(
        self, 
        func_name: str,
        call_param: List[str]  
    ) -> List[FunctionDefinition]:
        candidates = []
        # get all definitions of func_name
        for (file_path, name), definitions in self.function_index.items():
            if name == func_name:
                for defn in definitions:
                    if self._match_parameters(call_param, defn.func_params):
                        candidates.append(defn)
        return candidates
    
    def _infer_type(self, expr: str) -> List[str]:
        if expr.isdigit():
            return ["int", "Integer", "long", "Long", "short", "Short"]
        elif expr.replace('.', '', 1).isdigit():
            return ["float", "Float", "double", "Double"]
        elif expr.startswith('"') and expr.endswith('"') or expr.startswith("'") and expr.endswith("'"):
            if len(expr) == 3:  
                return ["char", "Character"]
            else:
                return ["str", "String"]
        else:
            return ["unknown"]

    def _match_parameters(
        self, 
        call_arg_exprs: List[str],  
        def_param_types: List[str]  
    ) -> bool:

        if len(call_arg_exprs) > len(def_param_types):
            return False
        
        call_param_types = [self._infer_type(expr) for expr in call_arg_exprs]
        
        for call_type_list, def_type in zip(call_param_types, def_param_types):
            if def_type == "unknown" or "unknown" in call_type_list:
                continue
            if def_type not in call_type_list:
                return False
        return True



    # tar3: find all caller
    # all caller 
    def analyze_function_calls(
        self, 
        file_path: str, 
        func_name: str
    ) -> FunctionCallAnalysisResult:
        normalized_path = str(Path(file_path).resolve())
        target_key = (normalized_path, func_name)
        
        target_definitions = self.function_index.get(target_key, [])
        if not target_definitions:
            return FunctionCallAnalysisResult(
                target_func=None,
                sub_calls=[],
                direct_calls=[]
            )
        

        sub_calls = []
        target_root = self.analyzer.parse_file(Path(normalized_path))
        if target_root:
            sub_calls.extend(self.analyzer._find_calls(target_root, target_definitions[0].start_line, target_definitions[0].end_line))
        
        direct_calls = self.direct_calls.get(target_key, [])
        
        return FunctionCallAnalysisResult(
            target_func=target_definitions[0],
            sub_calls=[{"func_name": sub_call['name'], "params": sub_call['params'], "line": sub_call['line']} for sub_call in sub_calls],
            direct_calls=direct_calls
        )



# target2： find a function init in project
# project/
# ├── src/
# │   ├── main.c
# │   └── utils.c
# └── include/
#     └── utils.h
# get one call init in project 
def find_call_init_in_project(
    project_dir: Path, 
    current_file: Path, 
    line: int,  # 1-based
    call_func_name: str,
    lang_config: LanguageConfig
) -> List[Dict]:
    """

    - project_dir: project root directory
    - current_file: current file path
    - line: line number where the call occurs
    - call_func_name: function name being called
    - lang_config: language configuration

    return:
    List[Tuple(file_path, start_line, end_line, code)] list of possible definition locations

    """

    analyzer = UniversalCodeAnalyzer(lang_config)
    project_analyzer = ProjectAnalyzer(lang_config)
    project_analyzer.build_index(project_dir)
    root = analyzer.parse_file(current_file)

    call_node = analyzer._find_calls_at_line(root, line)

    if not call_node:
        # global_info.error("No call found at line")
        return []
    call_args = call_node[0]['params']
    definitions = project_analyzer.find_matching_definitions(call_func_name, call_args)
    return [
        {
            "file": defn.file,
            "func_name": defn.func_name,
            "func_params": defn.func_params,
            "start_line": defn.start_line,
            "end_line": defn.end_line,
            "code": defn.code
        }
        for defn in definitions
    ]


# target3: find one func all call info in project
def find_func_call_info_in_project(file_path, project_dir, func_name, lang_config):
    project_analyzer = ProjectAnalyzer(lang_config)
    project_analyzer.build_index(project_dir)
    return project_analyzer.analyze_function_calls(file_path, func_name)









