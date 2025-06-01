from pathlib import Path
from tree_sitter import Parser, Language, Node
from functools import lru_cache, wraps
from typing import Dict, List, Optional, Callable, Type, Any, Union
import logging
from collections import deque, defaultdict
from dataclasses import dataclass


@dataclass
class LanguageConfig:
    name: str
    library_path: str
    file_patterns: List[str]
    node_types: Dict[str, str]
    library_functions: List[str]
    function_name_extractor: Callable[[Node], Optional[str]]
    call_resolver: Callable[[Node], Optional[str]]
    variable_extractor: Callable[[Node, Language], Optional[List[Dict]]]  
    call_params_extractor: Callable[[Node], List[str]]
    language: Optional[Language] = None  


# file level
class UniversalCodeAnalyzer:
    def __init__(self, config: LanguageConfig):
        self.config = config
        self.parser = Parser()
        self._init_parser()

    def _init_parser(self):
        if not Path(self.config.library_path).exists():
            raise FileNotFoundError(f"Language library not found: {self.config.library_path}")
    
        self.config.language = Language(self.config.library_path, self.config.name)
        self.parser.set_language(self.config.language)

    def _validate_config(self):
        required_keys = {'function_def', 'call_expr', 'variable_declaration'}
        if not required_keys.issubset(self.config.node_types.keys()):
            missing = required_keys - self.config.node_types.keys()
            raise ValueError(f"Missing required node types: {missing}")

    @lru_cache(maxsize=32)
    def parse_file(self, file_path: Path) -> Optional[Node]:
        if not file_path.exists():
            raise FileNotFoundError(file_path)
            
        with open(file_path, 'rb') as f:
            return self.parser.parse(f.read()).root_node

    # BFS
    def _iterative_traverse(self, node: Node, target_types: Union[str, List[str]]) -> List[Node]:
        results = []
        queue = deque([node])
        target_list = target_types if isinstance(target_types, list) else [target_types]
        while queue:
            current = queue.popleft()
            if current.type in target_list:
                results.append(current)
            queue.extend(current.children)
        return results
    
    # DFS
    # def _iterative_traverse(self, node: Node, target_types: Union[str, List[str]]) -> List[Node]:
    #     stack = [node]
    #     result = []
    #     target_list = target_types if isinstance(target_types, list) else [target_types]
    #     while stack:
    #         current = stack.pop()
    #         if current.type in target_list:
    #             result.append(current)
    #         stack.extend(current.children)
    #     return result

    
    
    ######################################  analyze_context in a given range
    def analyze_context(self, file_path: Path, start_line: int, end_line: int) -> Dict:
        root = self.parse_file(file_path)
        if not root:
            return {'file': str(file_path), 'value_info': [], 'func_info': [], 'call_info': []}

        return {
            'file': str(file_path),
            'value_info': self._find_values(root, start_line, end_line),
            'func_info': self._find_functions(root, start_line, end_line), # without node
            'call_info': self._find_calls(root, start_line, end_line)
        }

    # find funcs in a given range(start_line, end_line)
    def _find_functions(self, root: Node, start: int, end: int) -> List[Dict]:

        functions = []
        for node in self._iterative_traverse(root, self.config.node_types['function_def']):
            if self._is_in_range(node, start, end):
                if name := self.config.function_name_extractor(node):
                    # change 0-based to 1-based
                    func_start = node.start_point[0] + 1
                    func_end = node.end_point[0] + 1
                    func_params = self._extract_function_params(node)
                    functions.append({
                        'name': name,
                        "func_params": func_params,
                        'start_line': func_start,
                        'end_line': func_end,
                        'code': node.text.decode()
                    })
        return functions

    # find calls in a given range(start_line, end_line)
    def _find_calls(self, root: Node, start: int, end: int) -> List[Dict]:
        calls = []
        for node in self._iterative_traverse(root, self.config.node_types['call_expr']):
            if self._is_in_range(node, start, end):
                if call_name := self.config.call_resolver(node):
                    call_line = node.start_point[0] + 1  
                    calls.append({
                        'name': call_name,
                        'line': call_line,
                        'params': self.config.call_params_extractor(node)
                    })
        return calls

    # find values in a given range(start_line, end_line)
    def _find_values(self, root: Node, start: int, end: int) -> List[Dict]:
        values = []
        for node in self._iterative_traverse(root, self.config.node_types['variable_declaration']):
            if self._is_in_range(node, start, end):
                # struct first
                if self._is_struct_declaration(node):
                    var_name = self._extract_struct_variable_name(node)
                    var_type = self._extract_struct_variable_type(node)
                    values.append({
                        "struct": True,
                        "name": var_name,
                        "type": var_type,
                        "line": node.start_point[0] + 1,
                        "code": node.text.decode()
                        })
                    return values

                extracted = self.config.variable_extractor(node)
                if not extracted:
                    continue
    
                variables = extracted if isinstance(extracted, list) else [extracted]
                for var_info in variables:
                    line = node.start_point[0] + 1 
                    values.append({
                        "line": line,
                        "name": var_info.get("name"),
                        "type": var_info.get("type")
                    })
        return values
    
    def _is_in_range(self, node: Node, start_line: int, end_line: int) -> bool:
        node_start = node.start_point[0] + 1
        node_end = node.end_point[0] + 1
        return (node_start <= end_line) and (node_end >= start_line)
    
    def _is_struct_declaration(self, node: Node) -> bool: # c/cpp
        return (node.type == 'declaration' and any(child.type == 'struct_specifier' for child in node.children))

    def _extract_struct_variable_name(self, node: Node) -> str:
        declarator = node.child_by_field_name('declarator')
        if declarator and declarator.type == 'init_declarator':
            name_node = declarator.child_by_field_name('declarator')
        else:
            name_node = node.child_by_field_name('declarator')
        if name_node and name_node.type == 'identifier':
            return name_node.text.decode().strip()
        return ""

    def _extract_struct_variable_type(self, node: Node) -> str:
        type_node = node.child_by_field_name('type')
        if type_node and type_node.type == 'struct_specifier':
            struct_type = type_node.text.decode().strip()
            return struct_type
        return ""


    # get params of a function
    def _extract_function_params(self, node: Node) -> List[str]:
        # self.print_tree(node)
        # print("Extracting function parameters...")
        params = []
        for child in node.children:
            # java
            if child.type == 'formal_parameters':
                params_node = child
                if not params_node:
                    continue
                for param_child in params_node.children:
                    if param_child.type == 'formal_parameter':
                
                        type_node = param_child.child_by_field_name('type')
                        if type_node:
                            params.append(type_node.text.decode())
                        else:
                            param_type = self._extract_complex_type(param_child)
                            params.append(param_type)
                return params
            
            # c /cpp
            if child.type == 'function_declarator':
                print(child)
                params_node = child.child_by_field_name('parameters')
                if not params_node:
                    params_node = child.child_by_field_name('parameter_list')
                if not params_node:
                    return []  
                
                params = []
                for param_child in params_node.children:
                    if param_child.type == 'parameter_declaration':
                        type_node = param_child.child_by_field_name('type')
                        if type_node:
                            params.append(type_node.text.decode())
                        else:
                            param_type = self._extract_complex_type(param_child)
                            params.append(param_type)
                return params
        return [] 

    def _extract_complex_type(self, node: Node) -> str:
        type_parts = []
        for child in node.children:
            if child.type in ('type_identifier', 'primitive_type'):
                type_parts.append(child.text.decode())
            elif child.type in ('pointer_declarator', 'array_declarator'):
                type_parts.extend(self._extract_complex_type(child))
        return ' '.join(type_parts)
    ######################################  analyze_context in a given range

    # print tree 
    def print_tree(self, node: Node, indent: int = 0):
        print(' ' * indent + node.type)
        for child in node.children:
            self.print_tree(child, indent + 2)


    ##################### other
   
    def _find_functions_at_line(self, root: Node, line: int) -> List[Dict]: # with node for project
        functions = []
        for node in self._iterative_traverse(root, self.config.node_types['function_def']):

            func_start = node.start_point[0] + 1
            func_end = node.end_point[0] + 1
            
            if func_start <= line <= func_end:
                if name := self.config.function_name_extractor(node):
                    func_params = self._extract_function_params(node)
                    functions.append({
                        'name': name,
                        'func_params': func_params,
                        'start_line': func_start,
                        'end_line': func_end,
                        'code': node.text.decode(),
                        'node': node
                        })
        return functions

    def _find_calls_at_line(self, root: Node, line: int) -> List[Dict]:
        calls = []
        for node in self._iterative_traverse(root, self.config.node_types['call_expr']):
            call_line = node.start_point[0] + 1
            if call_line == line:
                if call_name := self.config.call_resolver(node):
                    calls.append({
                        'name': call_name,
                        'line': call_line,
                        'params': self.config.call_params_extractor(node),
                    })
        return calls    

    def call_params_extractor(node: Node) -> List[str]:
        args_node = node.child_by_field_name('arguments')
        if not args_node:
            return []
        
        params = []
        for child in args_node.children:
            if child.type == ',':
                continue  
            params.append(child.text.decode())
        return params
    
    def _find_calls_ret_node(self, root: Node, start: int, end: int) -> List[Dict]:
        calls = []
        for node in self._iterative_traverse(root, self.config.node_types['call_expr']):
            if self._is_in_range(node, start, end):
                if call_name := self.config.call_resolver(node):
                    call_line = node.start_point[0] + 1  
                    calls.append({
                        'name': call_name,
                        'line': call_line,
                        'params': self.config.call_params_extractor(node),
                        'node': node
                    })
        return calls
        
    


