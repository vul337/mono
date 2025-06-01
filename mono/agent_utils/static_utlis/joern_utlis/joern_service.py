import os
from pathlib import Path
from typing import Optional, Dict, Any, Union, List, Tuple
from collections import defaultdict
import networkx as nx
import json
from server_tools import JoernService
import re

root_path = ""


class JoernQueryService:
    def __init__(self, joern_service):
        self.jq = joern_service
        self.func = FunctionQueryService(joern_service)
        self.var = VariableQueryService(joern_service)
        self.code = CodeQueryService()
        self.caller = CallerQueryService(joern_service)
        self.callee = CalleeQueryService(joern_service)
        self.dependency = DependencyGraphService(joern_service)
        self.query = DirectQueryService(joern_service)


class DirectQueryService:
    def __init__(self, joern_service):
        self.jq = joern_service

    def query(self, query_string: str) -> List[Dict]:
        try:
            res = self.jq.query_json(query_string)
            if res and len(res) > 0:
                return res
            else:
                return "erorr query"
        except Exception as e:
            print(f"Error: {str(e)}")
            return "erorr query"

    def _query(self, query_string: str) -> None:
        return self.jq._query(query_string)


def check_code(code: str) -> bool:
    if "..." in code:
        return False
    # {} ; \n 
    if "{" in code or "}" in code or ";" in code or "\n" in code:
        return True

# func info = {
#     "id": 123, "_1"
#     "code": "int main() { return 0; }", "_2"
#     "lineNumber": 1, "_3"
#     "lineNumberEnd": 1, "_4"
#     "filename": "main.c" "_5"
# }
class FunctionQueryService:
    def __init__(self, joern_service):
        self.jq = joern_service

    def get_allfile_by_cpg(self) -> List[str]:
        query = """
        cpg.file.name.l
        """
        return self.jq.query_json(query)

    def fetch_allfunc_by_file(self, file_path: str) -> List[str]:
        query = f"""
        cpg.method
        .filter(m => m.code != "<empty>" 
                && m.code != "<global>" 
                && m.filename == "{file_path}")
        .map(m => m.name).l
        """
        return self.jq.query_json(query)

    def fetch_func_by_file_name(self, file_path: str, func_name: str, project_dir: str) -> List[Dict]:
        # && m.fullName.matches(".*\\\\.{file_path}.*"))
        query = f"""
        cpg.method
        .filter(m => m.code != "<empty>" 
                && m.code != "<global>" 
                && m.filename == "{file_path}"
                && m.name == "{func_name}")
        .map(m => (m.id, m.code, m.lineNumber, m.lineNumberEnd, m.fullName, m.filename))
        .l
        """
        res = self.jq.query_json(query)
        if res and len(res) > 0:
            for i in range(len(res)):
                if not check_code(res[i]['_2']):
                    res[i]['_2'] = get_file_code_by_lines(project_dir, file_path, res[i]['_3'], res[i]['_4'])
        return res

    def fetch_func_by_file_and_line(self, file_path: str, line: int, project_dir: str) -> List[Dict]:
        query = f"""
        cpg.method
        .filter(m => m.code != "<empty>" 
                && m.code != "<global>" 
                && m.filename == "{file_path}"
                && m.lineNumber.exists(_ <= {line}) 
                && m.lineNumberEnd.exists(_ >= {line}))
        .map(m => (m.id, m.code, m.lineNumber, m.lineNumberEnd, m.fullName, m.filename)).l
        """
        res = self.jq.query_json(query)
        if res and len(res) > 0:
            for i in range(len(res)):
                if not check_code(res[i]['_2']):
                    res[i]['_2'] = get_file_code_by_lines(project_dir, file_path, res[i]['_3'], res[i]['_4'])
        return res

    def fetch_func_by_file_lines(self, file_path: str, start_line: int, end_line: int, project_dir: str) -> List[Dict]:
        query = f"""
        cpg.method
        .filter(m => m.code != "<empty>"
                && m.code != "<global>"
                && m.filename == "{file_path}"
                && m.lineNumber.exists(_ >= {start_line})
                && m.lineNumberEnd.exists(_ <= {end_line}))
        .map(m => (m.id, m.code, m.lineNumber, m.lineNumberEnd, m.fullName, m.filename)).l
        """
        res = self.jq.query_json(query)
        if res and len(res) > 0:
            for i in range(len(res)):
                if not check_code(res[i]['_2']):
                    res[i]['_2'] = get_file_code_by_lines(project_dir, file_path, res[i]['_3'], res[i]['_4'])
        return res

    def _is_valid_fuzzy_match(self, func_name: str, call_name: str) -> bool:
        pattern = rf'(^|[^\w]){re.escape(func_name)}($|[^\w])'
        return re.search(pattern, call_name) is not None

    def fetch_func_by_name(self, func_name: str, project_dir: str) -> List[Dict]:
        query_exact = f"""
        cpg.method
        .filter(m => m.code != "<empty>" && m.code != "<global>" && m.name == "{func_name}")
        .map(m => (m.id, m.code, m.lineNumber, m.lineNumberEnd, m.fullName, m.filename))
        .dedup
        .l
        """
        res = self.jq.query_json(query_exact)

        if not res or len(res) == 0:
            query_fuzzy = f"""
            cpg.method
            .filter(m => m.code != "<empty>" && m.code != "<global>" && m.name.matches(".*{func_name}.*"))
            .map(m => (m.id, m.name, m.code, m.lineNumber, m.lineNumberEnd, m.fullName, m.filename))
            .l
            """
            fuzzy_result = self.jq.query_json(query_fuzzy)
            if fuzzy_result and len(fuzzy_result) > 0:
                res = [r for r in fuzzy_result if self._is_valid_fuzzy_match(func_name, r['_2'])]
                for r in res:
                    r['_1'], r['_2'], r['_3'], r['_4'], r['_5'], r['_6'] = r['_1'], r['_3'], r['_4'], r['_5'], r['_6'], r['_7']
                
        if not res or len(res) == 0:
            # If both exact and fuzzy name matches fail, try fullName match
            query_fullname = f"""
            cpg.method
            .filter(m => m.code != "<empty>" && m.code != "<global>" && m.fullName == "{func_name}")
            .map(m => (m.id, m.code, m.lineNumber, m.lineNumberEnd, m.fullName, m.filename))
            .dedup
            .l
            """
            res = self.jq.query_json(query_fullname)

        if not res or len(res) == 0:
            return []
        
        for r in res:
            code = r['_2']
            if not check_code(code):
                r['_2'] = get_file_code_by_lines(project_dir, r['_6'], r['_3'], r['_4'])
        
        return res



# value init = {
#  
class VariableQueryService:
    def __init__(self, joern_service):
        self.jq = joern_service

    def fetch_id_by_valuename_line(self, valuename: str, line: int) -> List[int]:
        query = f"""
        cpg.identifier
        .filter(i => i.name == "{valuename}" 
                && i.lineNumber.exists(_ == {line}))
        .id.l
        """
        return self.jq.query_json(query)


    def get_item_by_id(self, item_type: str, item_id: int) -> Optional[Dict]:
        query = f"""
        cpg.{item_type}.id({item_id}L).l
        """
        item = self.jq.query_json(query)
        return item[0] if item else None

    def fetch_member_or_value_by_file_name(self, value_name: str, file_path: str = None) -> dict:
        """
        Robust fetch for variable or struct member initialization.
        Supports:
        - Local/global variables
        - Struct & pointer field access
        - Nested field resolution (e.g., p->inner.a)
        - Variable declarations (e.g., NestedStruct *pns = ...)
        - File-scoped fallback to project-wide
        - Typedef tracing for the struct that owns the final field
        """

        def query_with_fallback(query_func):
            result = query_func(file_path)
            return result if result else query_func(None)
            
        name = value_name
        results = []
        struct_var = None
        struct_type = None
        struct_def = None

        file_pattern = lambda fp: fp or ".*"

        # === Detect field access structure
        is_member = "->" in name or "." in name
        field_path = name.replace("->", ".").split(".") if is_member else []
        base_var = field_path[0] if is_member else None
        nested_fields = field_path[1:] if len(field_path) > 1 else []

        # === Step 1: Try exact assignment
        def exact_var_query(fp):
            return self.jq.query_json(f'''
            cpg.call.assignment
            .target
            .code("{name}")
            .where(_.file.name("{file_pattern(fp)}"))
            .flatMap {{ a =>
                Option(a.astParent).map {{ p =>
                    Map(
                        "full_code" -> p.code,
                        "line" -> a.lineNumber,
                        "method" -> a.method.fullName
                    )
                }}
            }}
            .l
            ''')
        results = query_with_fallback(exact_var_query)

        # === Step 2: Fuzzy assignment
        if not results:
            def fuzzy_var_query(fp):
                return self.jq.query_json(f'''
                cpg.call.assignment
                .target
                .filter(_.code.matches(".*{name}.*"))
                .where(_.file.name("{file_pattern(fp)}"))
                .flatMap {{ a =>
                    Option(a.astParent).map {{ p =>
                        Map(
                            "full_code" -> p.code,
                            "line" -> a.lineNumber,
                            "method" -> a.method.fullName
                        )
                    }}
                }}
                .l
                ''')
            results = query_with_fallback(fuzzy_var_query)

        # === Step 3: Struct member fallbacks
        if is_member and not results:
            def direct_struct_query(fp):
                return self.jq.query_json(f'''
                cpg.call
                .where(_.code("{name}"))
                .where(_.file.name("{file_pattern(fp)}"))
                .flatMap {{ a =>
                    Option(a.astParent).map {{ p =>
                        Map(
                            "full_code" -> p.code,
                            "line" -> a.lineNumber,
                            "method" -> a.method.fullName
                        )
                    }}
                }}
                .l
                ''')
            results = query_with_fallback(direct_struct_query)

        if is_member and not results:
            def regex_struct_query(fp):
                regex_name = name.replace(".", "\\.")
                return self.jq.query_json(f'''
                cpg.call
                .filter(_.code.matches(".*{regex_name}.*"))
                .where(_.file.name("{file_pattern(fp)}"))
                .flatMap {{ a =>
                    Option(a.astParent).map {{ p =>
                        Map(
                            "full_code" -> p.code,
                            "line" -> a.lineNumber,
                            "method" -> a.method.fullName
                        )
                    }}
                }}
                .l
                ''')
            results = query_with_fallback(regex_struct_query)

        if is_member and not results:
            def fieldident_query(fp):
                return self.jq.query_json(f'''
                cpg.fieldIdentifier
                .where(_.code("{field_path[-1]}"))
                .inCall
                .filter(_.code.matches(".*{name}.*"))
                .where(_.file.name("{file_pattern(fp)}"))
                .flatMap {{ a =>
                    Option(a.astParent).map {{ p =>
                        Map(
                            "full_code" -> p.code,
                            "line" -> a.lineNumber,
                            "method" -> a.method.fullName
                        )
                    }}
                }}
                .l
                ''')
            results = query_with_fallback(fieldident_query)

        # # === Step 4: Global variable fallback
        # if not results: 
        #     def call_fallback(fp):
        #         return self.jq.query_json(f'''
        #         cpg.call
        #         .filter(_.code.matches(".*{name}.*"))
        #         .where(_.file.name("{file_pattern(fp)}"))
        #         .map {{ c =>
        #             Map("full_code" -> c.code, "line" -> c.lineNumber, "method" -> c.method.fullName)
        #         }}
        #         .l
        #         ''')
        #     results = query_with_fallback(call_fallback)

        # === Step 5: Always try to get type for non-member variable
        # have results but not member
        if not is_member:
            # no FullMethodName
            def local_decl_query(fp):
                query = (f'''
                cpg.local
                .name("{name}")
                .where(_.file.name("{file_pattern(fp)}"))
                .flatMap {{ a =>
                    Option(a.astParent).map {{ p =>
                        Map(
                            "full_code" -> p.code,
                            "line" -> a.lineNumber,
                            "method" -> a.method.fullName
                        )
                    }}
                }}
                .l
                ''')
                return self.jq.query_json(query)
            local_result = query_with_fallback(local_decl_query)
            if local_result:
                if not results:
                    results = local_result
                    for item in results:
                        item["method"] = None
                struct_type = local_result[0].get("type")
           

        # === Step 6: Struct type resolution (for members)
        if is_member:
            struct_var = base_var
            current_type = None
            resolved_type = None

            # Resolve base variable type
            type_q = f'cpg.identifier.name("{base_var}").typeFullName.l'
            type_res = self.jq.query_json(type_q)
            if type_res:
                current_type = type_res[0].strip('"')

            # Fallback from member field
            if not current_type:
                member_type_q = f'cpg.member.name("{base_var}").typeFullName.l'
                type_res = self.jq.query_json(member_type_q)
                if type_res:
                    current_type = type_res[0].strip('"')

            # Walk nested fields and stop at parent struct of final field
            for i, field in enumerate(nested_fields):
                if not current_type:
                    break
                field_type_q = f'cpg.typeDecl.name("{current_type.strip("*")}").member.name("{field}").typeFullName.l'
                field_type_res = self.jq.query_json(field_type_q)
                if field_type_res:
                    if i == len(nested_fields) - 1:
                        resolved_type = current_type
                    current_type = field_type_res[0].strip('"')

            struct_type = current_type
        
        if not results: # think it is a struct name
            struct_type = name

        # === Step 7: typedef resolution
        if struct_type:
            typedef_q = f'cpg.typeDecl.name("{struct_type.strip("*")}").code.l'
            typedef_res = self.jq.query_json(typedef_q)
            if typedef_res:
                struct_def = "\n\n".join(typedef_res)

        return {
            "matches": [(item["full_code"], item.get("line"), item["method"]) for item in results[:5]] if results else [],
            "struct_var": base_var if is_member else name,
            "struct_type": struct_type,
            "struct_definition": struct_def
        }




class CodeQueryService:
    def __init__(self):
        pass
    
    def fetch_file_code_by_lines(self, project_dir: str, file_path: str, start_line: int, end_line: int) -> str:
        raw_project = os.path.abspath(project_dir)
  
        possible_paths = [
            os.path.join(raw_project, file_path),
        ]
        
        for full_path in possible_paths:
            if os.path.exists(full_path):
                return _read_file_lines(full_path, start_line, end_line)
        
        path_parts = file_path.split(os.path.sep)
        target_dir = path_parts[0] 
        
        for root, dirs, _ in os.walk(raw_project):
            if target_dir in dirs:  
                matched_dir = os.path.join(root, target_dir)
                remaining_path = os.path.sep.join(path_parts[1:])  
                full_path = os.path.join(matched_dir, remaining_path)
                
                if os.path.exists(full_path):
                    return _read_file_lines(full_path, start_line, end_line)
        

        for root, _, files in os.walk(raw_project):
            for file in files:
                current_file_path = os.path.join(root, file)
                if file_path in current_file_path:  
                    return _read_file_lines(current_file_path, start_line, end_line)
        
        return "error code"

from pathlib import Path
from typing import List


FUNCTION_HEAD_RE = re.compile(
    r"""
    ^\s*
    (?:                             
        [A-Za-z_]\w*                
        \s*\([^)]*\)             
        \s*\n\s*                  
    )*
    (?:[\w\*\&\s:<>~]+\s+)?        
    [A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*  
    \s*\([^;{]*\)                   
    [^{;]*\{                   
    """,
    re.MULTILINE | re.DOTALL | re.VERBOSE,
)

def _find_function_start(lines: List[str]) -> int:
    for idx, line in enumerate(lines, 1):
        if FUNCTION_HEAD_RE.match(line):
            return idx
    return 1

def _read_file_lines(file_path: str, start_line: int, end_line: int) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            tmp = end_line - start_line
            if (start_line == 1 or start_line == 0) and len(lines) > 0:
                actual_start = _find_function_start(lines)
                start_line = max(1, actual_start)
                end_line = min((start_line + tmp), len(lines))
                # print(f"start_line: {start_line}, end_line: {end_line}")
                
            start_line = max(1, start_line)
            end_line = min(len(lines), end_line)
            return ''.join(lines[start_line-1:end_line])
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return ""

# caller info = {
#     "caller_name": 123, "_1"
#     "caller_func": "int main() { return 0; }", "_2"
#     "line": "11", "_3"
#    "file_path": "main.c", "_4"
class CallerQueryService:
    def __init__(self, joern_service):
        self.jq = joern_service
    def c_find_references_for_file(self, file_path: str) -> List[str]:
        query = f"""
        cpg.imports
          .filter(_.importedEntity.contains("{file_path}"))
          .file.name
          .dedup
          .l
        """
        return self.jq.query_json(query)

    # maybe without code return
    def find_caller_for_func(self, file_path: str = None, func_name: str = None, project_dir: str = None) -> List[Dict]:
        exact_query = f"""
            cpg.call
              .nameExact("{func_name}")
              .filterNot(_.name.startsWith("<operator>"))
              .map(c => (c.name, c.methodFullName, c.code, c.lineNumber, c.location.filename))
              .dedup
              .l
        """
        references = self.jq.query_json(exact_query)

        if not references:
            fuzzy_query = f"""
                cpg.call
                  .name(".*{func_name}.*")
                  .filterNot(_.name.startsWith("<operator>"))
                  .map(c => (c.name, c.methodFullName, c.code, c.lineNumber, c.location.filename))
                  .dedup
                  .l
            """
            fuzzy_result = self.jq.query_json(fuzzy_query)
            references = [r for r in fuzzy_result if self._is_valid_fuzzy_match(func_name, r['_1'])]
        
        # print(references)
        if not references:
            return []

        # print(references)
        self_references = []
        other_references = []
        
        for ref in references:
            if ref['_4'] == file_path:
                self_references.append(ref)
            else:
                other_references.append(ref)

        results = []
        processed = 0
        max_results = 8
        for ref in self_references + other_references:
            if processed >= max_results:
                break
            
            ref_line = ref['_4']
            ref_path = ref['_5']
            ref_code = ref['_3']

            try:
                caller_code = get_file_code_by_lines(project_dir, ref_path, ref_line-10, ref_line+10)
            except Exception as e:
                continue


            results.append({
                "caller_name": ref['_2'],
                "caller_func": caller_code,
                "call_line": ref_line,
                "call_code": ref_code,
                "call_path": ref_path
            })

            processed += 1

        return results


    def find_caller_info_for_func(self, file_path: str = None, func_name: str = None, project_dir: str = None) -> List[Dict]:
        exact_query = f"""
            cpg.call
              .nameExact("{func_name}")
              .filterNot(_.name.startsWith("<operator>"))
              .map(c => (c.name, c.methodFullName, c.code, c.lineNumber, c.location.filename))
              .dedup
              .l
        """
        references = self.jq.query_json(exact_query)
    
        if not references:
            fuzzy_query = f"""
                cpg.call
                  .name(".*{func_name}.*")
                  .filterNot(_.name.startsWith("<operator>"))
                  .map(c => (c.name, c.methodFullName, c.code, c.lineNumber, c.location.filename))
                  .dedup
                  .l
            """
            fuzzy_result = self.jq.query_json(fuzzy_query)
            references = [r for r in fuzzy_result if self._is_valid_fuzzy_match(func_name, r['_1'])]

        # print(references)
        if not references:
            return []

        results = []
        processed = 0
        max_results = 8

        prioritized_refs = [r for r in references if file_path and r['_5'] == file_path] # most related
        fallback_refs = [r for r in references if not (file_path and r['_5'] == file_path)]

        for ref in prioritized_refs + fallback_refs:
            if processed >= max_results:
                break
            
            ref_line = ref['_4']
            ref_path = ref['_5']
            ref_code = ref['_3']

            try:
                caller_info = self._fetch_func_by_file_and_line(ref_path, ref_line, project_dir)
            except Exception as e:
                continue

            if caller_info and len(caller_info) > 0:
                caller = caller_info[0]
                caller_code = caller['_2']
                caller_start = caller['_3']
                caller_end = caller['_4']

                results.append({
                    "caller_func": caller_code,
                    "caller_start": caller_start,
                    "caller_end": caller_end,
                    "call_line": ref_line,
                    "call_code": ref_code,
                    "call_path": ref_path
                })

                processed += 1

        return results

    def _is_valid_fuzzy_match(self, func_name: str, call_name: str) -> bool:
        pattern = rf'(^|[^\w]){re.escape(func_name)}($|[^\w])'
        return re.search(pattern, call_name) is not None

    def _fetch_func_by_file_and_line(self, file_path: str, lineno: int, project_dir: str) -> List[Dict]:
        query = f"""
        cpg.method
        .filter(m => m.code != "<empty>" 
                && m.code != "<global>" 
                && m.filename == "{file_path}"
                && m.lineNumber.exists(_ <= {lineno}) 
                && m.lineNumberEnd.exists(_ >= {lineno}))
        .map(m => (m.id, m.code, m.lineNumber, m.lineNumberEnd, m.fullName)).l
        """
        res = self.jq.query_json(query)
        if res and len(res) > 0:
            for i in range(len(res)):
                # print(res[i]['_2'])
                if not check_code(res[i]['_2']):
                    res[i]['_2'] = get_file_code_by_lines(project_dir, file_path, res[i]['_3'], res[i]['_4'])
        return res


    def java_find_references_for_file(self, file_path: str) -> List[str]:
        class_name = self._java_file_path_to_class_name(file_path)
        if not class_name:
            return []
        
        query = f"""
        cpg.imports
          .filter(_.importedEntity.contains("{class_name}"))
          .file.name
          .dedup
          .l
        """
        try:
            return self.jq.query_json(query)
        except Exception as e:
            print(f"Error: {str(e)}")
            return []

    def _java_file_path_to_class_name(self, file_path: str) -> Optional[str]:
        try:
            normalized = os.path.normpath(file_path).split(os.sep)
            for i, part in enumerate(normalized):
                if part == 'src':
                    if i+2 < len(normalized) and normalized[i+1] == 'main' and normalized[i+2] == 'java':
                        java_root = i+3
                    else:
                        java_root = i+1
                    break
            else:
                raise ValueError("Invalid source file path")

            package_parts = normalized[java_root:-1]
            class_name = os.path.splitext(normalized[-1])[0]
            
            if not package_parts or not class_name:
                raise ValueError("Invalid file path")
                
            return '.'.join(package_parts + [class_name])
        
        except Exception as e:
            print(f"Error: {str(e)}")
            return None

    
    def get_caller_chain_for_func(self, project_dir: str, file_path: str, func_name: str, max_depth: int = 1, draw_graph: bool=False) -> List[Dict]:
        caller_chain, _, _ = get_caller_chain(
            self.jq,
            project_dir=project_dir,
            file_path=file_path,
            func_name=func_name,
            max_depth=max_depth,
            draw_graph=draw_graph
        )
        return caller_chain


class CalleeQueryService:
    def __init__(self, joern_service):
        self.jq = joern_service

    def fetch_callees_by_file_func_line(self, file_path: str, func_name: str, line: int) -> List[Dict]:
        query = f"""
        cpg.method
            .filter(m => m.code != "<empty>" 
                    && m.code != "<global>" 
                    && m.filename == "{file_path}"
                    && m.name == "{func_name}")
            .call
            .filter(c => c.lineNumber.exists(_ == {line}))
            .map(c => (c.methodFullName, c.code, c.lineNumber))
            .dedup
            .l
        """
        return self.jq.query_json(query)

    def fetch_callee_by_file_func(self, file_path: str, func_name: str) -> List[Dict]:
        query = f"""
        cpg.method
            .filter(m => m.code != "<empty>" 
                    && m.code != "<global>" 
                    && m.filename == "{file_path}"
                    && m.name == "{func_name}")
            .call
            .map(c => (c.methodFullName, c.code, c.lineNumber))
            .dedup
            .l
        """
        return self.jq.query_json(query)

class DependencyGraphService:
    def __init__(self, joern_service):
        self.jq = joern_service

    def get_ids_by_funclist(self, func_list: List[str], project_dir: str) -> List[int]:
        JQ = JoernQueryService(self.jq)
        ids = []
        for func in func_list:
            id = JQ.func.fetch_func_by_name(func, project_dir)[0]['_1']
            if id not in ids:
                ids.append(id)
        return ids

    def generate_pdg_for_method(self, method_ids: List[int], draw_graph: List[str] = None) -> Dict:
        raw_pdg = self.dump_method_pdg(method_ids)
        if 'functions' not in raw_pdg or len(raw_pdg['functions']) == 0:
            return None
        
        pdg_dict = {}
        for func in raw_pdg['functions']:
            func_name = func['function']
            ast_graph = nx.DiGraph()
            cfg_graph = nx.DiGraph()
            dfg_graph = nx.DiGraph()
            cross_pdg = nx.DiGraph()
            ddg_graph = nx.DiGraph()
            cdg_graph = nx.DiGraph()

            # Build DFG
            for flow in func['PDG']:
                prev_node = None
                for node in flow:
                    node_name = node['id']
                    node_attr = {
                        'location': node['location'],
                        'id': node['id'],
                        'code': node["code"],
                    }
                    dfg_graph.add_node(node_name, **node_attr)
                    if prev_node:
                        dfg_graph.add_edge(prev_node, node_name)
                    prev_node = node_name

            # Build CrossPDG
            for flow in func['CrossPDG']:
                prev_node = None
                for node in flow:
                    node_name = node['id']
                    node_attr = {
                        'location': node['location'],
                        'id': node['id'],
                        'code': node["code"],
                    }
                    cross_pdg.add_node(node_name, **node_attr)
                    if prev_node:
                        cross_pdg.add_edge(prev_node, node_name)
                    prev_node = node_name

            # Build DDG and CDG
            for gtype, graph in [('DDG', ddg_graph), ('CDG', cdg_graph)]:
                for node in func[gtype]['nodes']:
                    attr = {
                        'id': node['id'],
                        'location': node['location'],
                        'code': node['code'],
                    }
                    graph.add_node(node['id'], **attr)
                for edge in func[gtype]['edges']:
                    edge_attr = {
                        'label': edge['label'],
                    }
                    graph.add_edge(edge['src'], edge['dst'], **edge_attr)

            # Build AST and CFG
            for gtype, graph in [('AST', ast_graph), ('CFG', cfg_graph)]:
                for node in func[gtype]:
                    attr = {
                        'id': node['id'],
                        'location': node['location'],
                        'code': node['code'],
                    }
                    graph.add_node(node['id'], **attr)
                    for edge in node['edges']:
                        if edge['label'] != gtype:
                            continue
                        edge_attr = {
                            'label': edge['label'],
                        }
                        graph.add_edge(edge['src'], edge['dst'], **edge_attr)

            pdg_dict[func_name] = {
                'AST': ast_graph,
                'CFG': cfg_graph,
                'DFG': dfg_graph,
                'DDG': ddg_graph,
                'CDG': cdg_graph,
                "CrossPDG": cross_pdg,
            }

            if draw_graph:
                graph_mapping = {
                    'AST': ast_graph,
                    'CFG': cfg_graph,
                    'DFG': dfg_graph,
                    'DDG': ddg_graph,
                    'CDG': cdg_graph,
                    'CrossPDG': cross_pdg
                }
                
                for graph_name in draw_graph:
                    if graph_name in graph_mapping:
                        self._draw_graph(graph_mapping[graph_name], graph_name, func_name)
        
        return pdg_dict

    def _draw_graph(self, G: nx.DiGraph, graph_type: str, func_name: str) -> None:
        import matplotlib.pyplot as plt
        """Helper method to draw a single graph."""
        if not G or len(G.nodes) == 0:
            print(f"No nodes to draw for {graph_type} graph of {func_name}")
            return
            
        try:
            # Find roots (nodes with no incoming edges)
            roots = [node for node in G.nodes if G.in_degree(node) == 0]
            if not roots:
                print(f"No root node found for {graph_type} graph of {func_name}")
                return
                
            root = roots[0] if roots else list(G.nodes)[0]
            
            try:
                depths = nx.shortest_path_length(G, root)
            except nx.NetworkXError:
                depths = {node: 0 for node in G.nodes}
                
            depth_nodes = defaultdict(list)
            for node, depth in depths.items():
                depth_nodes[depth].append(node)
            
            pos = {}
            for depth, nodes in depth_nodes.items():
                n = len(nodes)
                x = [(i - n/2) * 2 for i in range(n)]  
                y = [-depth * 2 for _ in nodes]   
                for node, (xi, yi) in zip(nodes, zip(x, y)):
                    pos[node] = (xi, yi)

            plt.figure(figsize=(12, 8))
        
            node_labels = {}
            for n in G.nodes:
                label_parts = []
                
                try:
                    label_parts.append(str(n))
                except Exception:
                    label_parts.append("?")
                    
       
                try:
                    if 'code' in G.nodes[n] and G.nodes[n]['code']:
                        label_parts.append(str(G.nodes[n]['code']))
                except Exception:
                    pass
                    
     
                try:
                    if 'location' in G.nodes[n] and G.nodes[n]['location']:
                        label_parts.append(str(G.nodes[n]['location']))
                except Exception:
                    pass
                    
                node_labels[n] = "\n".join(label_parts) if label_parts else str(n)

    
            nx.draw(
                G, pos,
                labels=node_labels,
                with_labels=True,
                node_color='lightblue',
                node_size=1500,
                font_size=8,
                arrowsize=20,
                edge_color='gray'
            )
            plt.title(f"{graph_type} Graph for {func_name}", pad=20)
            plt.tight_layout()
            plt.show()
            
        except Exception as e:
            print(f"Failed to draw {graph_type} graph for {func_name}: {str(e)}")
            # Attempt a simple circular layout as fallback
            try:
                plt.figure(figsize=(12, 8))
                nx.draw(G, with_labels=True, node_color='lightblue')
                plt.title(f"{graph_type} Graph for {func_name} (Fallback)", pad=20)
                plt.show()
            except Exception as e2:
                print(f"Fallback drawing also failed: {str(e2)}")

    def dump_method_pdg(self, method_ids: List[int]) -> Dict:
        method_ids_str = [f"{id}L" for id in method_ids]
        method_ids = ",".join(method_ids_str)
        query = f"""
            val targetMethods = cpg.method.id({method_ids}).toList
        """
        self.jq._query(query)
        script_path = "scripts/extract_pdg.sc"
        pdg_str = self.jq.run_script(script_path)
        return json.loads(pdg_str)

    def save_all_nodes(self, save_dir: str) -> None:
        self.jq._query(f"val save_dir = \"{save_dir}\"")
        script_path = "scripts/get_all.sc"
        self.jq.run_script(script_path)


#    This function retrieves the caller chain for a given Java function.
#    It uses a recursive approach to find all callers up to a specified depth.
#    Returns a list of caller information, the updated node ID, and an optional graph.
def get_caller_chain(
    jq: JoernService,
    project_dir: str,
    file_path: str,
    func_name: str,
    depth: int = 0,
    max_depth: int = 1,
    cache: Optional[Dict[Tuple[str, str], Dict[int, Dict]]] = None,
    node_id: int = 0,
    node_parent: Optional[int] = None,
    draw_graph: bool = False
) -> Tuple[List[Dict], int, Optional[nx.DiGraph]]:

    JQ = JoernQueryService(jq)
    if cache is None:
        cache = {}

    if depth > max_depth:
        return [], node_id, None

    key = (file_path, func_name)
    if key in cache:
        return list(cache[key].values()), node_id, None

    caller_chain = []
    G = nx.DiGraph() if draw_graph else None
    
    if node_id == 0:
        code = ""
        info = JQ.func.fetch_func_by_file_name(file_path, func_name, project_dir)
        if info:
            code = info[0]['_2']
        caller_info = {
            'root_func': func_name,
            'file_path': file_path,
            'code': code,
            'depth': 0,
            'node_id': 1, 
            'node_parent': None
        }
        caller_chain.append(caller_info)
        if G is not None:
            G.add_node(1, label="Root", func=func_name, file=file_path)
        node_id = 1
        current_node_id = node_id
    else:
        current_node_id = node_parent  

    references = JQ.caller.find_caller_for_func(file_path, func_name)
    # print(f"find_caller_for_func: {file_path}, {func_name}, {references}")
    self_references, other_references = references
    all_references = other_references + self_references 

    for ref in all_references:
        call_method = ref['_1']
        call_line = ref['_3']
        caller_file = ref['_4']
        
        caller_func_info = JQ.func.fetch_func_by_file_and_line(caller_file, call_line, project_dir)
        # print(f"caller_func_info: {caller_func_info}")
        if not caller_func_info:
            continue

        caller_id = caller_func_info[0]['_1']
        caller_code = caller_func_info[0]['_2']
        caller_func = caller_func_info[0]['_5']
        # if len(caller_func) == len(func_name):
        #     output_file_path = root_path + caller_file
        #     caller_code = JQ.code.get_file_code_by_lines(output_file_path, caller_func_info[0]['_3'], caller_func_info[0]['_4'])
        #     # print(f"caller_code: {caller_code}")
        if not caller_code:
            continue
 
        node_id += 1
        caller_info = {
            'caller_id': caller_id,
            'caller_func': caller_func,
            'file_path': caller_file,
            'call_method': call_method,
            'code': caller_code,
            'line_number': call_line,
            'depth': depth + 1,
            'node_id': node_id,
            'node_parent': current_node_id 
        }
        caller_chain.append(caller_info)
        
        if G is not None:
            G.add_node(
                node_id, 
                label=str(node_id),
                func=caller_func,
                file=caller_file,
                line=call_line
            )
            G.add_edge(current_node_id, node_id)

        caller_func_name = caller_func.split("(")[0].split(" ")[-1]

        if depth + 1 <= max_depth:  
            sub_chain, updated_node_id, _ = get_caller_chain(
                jq, project_dir, caller_file, caller_func_name, 
                depth + 1, max_depth, cache, node_id, node_parent=node_id,
                draw_graph=False  
            )
            caller_chain.extend(sub_chain)
            node_id = updated_node_id  

    cache[key] = {node['node_id']: node for node in caller_chain} 
    
    if draw_graph and G is not None:
        caller_draw_graph(G)
    
    return list(cache[key].values()), node_id, G if draw_graph else None

def caller_draw_graph(G: nx.DiGraph) -> None:
    import matplotlib.pyplot as plt
    roots = [node for node in G.nodes if G.in_degree(node) == 0]
    if not roots:
        return
        
    root = roots[0]
    depths = nx.shortest_path_length(G, root)
    depth_nodes = defaultdict(list)
    for node, depth in depths.items():
        depth_nodes[depth].append(node)
    
    pos = {}
    for depth, nodes in depth_nodes.items():
        n = len(nodes)
        x = [(i - n/2) * 2 for i in range(n)]  
        y = [-depth * 2 for _ in nodes]   
        for node, (xi, yi) in zip(nodes, zip(x, y)):
            pos[node] = (xi, yi)

    plt.figure(figsize=(12, 8))
    node_labels = {
        n: f"{n}\n{G.nodes[n]['func'].split('(')[0]}\n{G.nodes[n]['file'].split('/')[-1]}"
        for n in G.nodes
    }
    
    nx.draw(
        G, pos,
        labels=node_labels,
        with_labels=True,
        node_color='lightblue',
        node_size=1500,
        font_size=8,
        arrowsize=20,
        edge_color='gray'
    )
    plt.title("Caller Chain Graph", pad=20)
    plt.tight_layout()
    plt.show()


#     @staticmethod
    # the file_path is the absolute path
    # the start_line and end_line are 1-based
import os

def get_file_code_by_lines(raw_project: str, file_path: str, start_line: int, end_line: int) -> str:
    raw_project = os.path.abspath(raw_project)
    
    possible_paths = [
        os.path.join(raw_project, file_path),
    ]
    
    for full_path in possible_paths:
        if os.path.exists(full_path):
            return _read_file_lines(full_path, start_line, end_line)
    
    path_parts = file_path.split(os.path.sep)
    target_dir = path_parts[0] 
    
    for root, dirs, _ in os.walk(raw_project):
        if target_dir in dirs:  
            matched_dir = os.path.join(root, target_dir)
            remaining_path = os.path.sep.join(path_parts[1:])  
            full_path = os.path.join(matched_dir, remaining_path)
            
            if os.path.exists(full_path):
                return _read_file_lines(full_path, start_line, end_line)
    

    for root, _, files in os.walk(raw_project):
        for file in files:
            current_file_path = os.path.join(root, file)
            if file_path in current_file_path:  
                return _read_file_lines(current_file_path, start_line, end_line)
    
    return "error code"





# caller old
# def find_caller_info_for_func(self, file_path: str = None, func_name: str = None, project_dir: str = None) -> List[Dict]:
#         call_query = f"""
#         cpg.call
#           .name(".*{func_name}.*")      
#           .filterNot(_.name.contains("<operator>"))  
#           .map(c => (c.methodFullName, c.code, c.lineNumber, c.location.filename))
#           .dedup                     
#           .l
#         """ # c.methodFullName is the func we query, but we need to get the caller 
#         references = self.jq.query_json(call_query)
#         # print(references)
#         # use line and file to get the caller
#         self_references = []
#         other_references = []
#         for ref in references:
#             new_ref = {}
#             ref_line = ref['_3']
#             ref_path = ref['_4']
#             ref_code = ref['_2']
#             caller_info = self._fetch_func_by_file_and_line(ref_path, ref_line, project_dir)
#             # print(caller_info)
#             if caller_info:
#                 caller_func = caller_info[0]['_5']
#                 caller_all_code = caller_info[0]['_2']
#                 caller_start = caller_info[0]['_3']
#                 caller_end = caller_info[0]['_4']
#                 new_ref = {
#                     "caller_func": caller_func,
#                     "caller_code": caller_all_code,
#                     "caller_start": caller_start,
#                     "caller_end": caller_end,
#                     "call_line": ref_line,
#                     "call_code": ref_code,
#                     "call_path": ref_path
#                 }
#             if ref_path == file_path:
#                 self_references.append(new_ref)
#             else:
#                 other_references.append(new_ref)
#         return self_references, other_references

#     def _fetch_func_by_file_and_line(self, file_path: str, lineno: int, project_dir: str) -> List[Dict]:
#         query = f"""
#         cpg.method
#         .filter(m => m.code != "<empty>" 
#                 && m.code != "<global>" 
#                 && m.filename == "{file_path}"
#                 && m.lineNumber.exists(_ <= {lineno}) 
#                 && m.lineNumberEnd.exists(_ >= {lineno}))
#         .map(m => (m.id, m.code, m.lineNumber, m.lineNumberEnd, m.fullName)).l
#         """
#         res = self.jq.query_json(query)
#         if res and len(res) > 0:
#             for i in range(len(res)):
#                 # print(res[i]['_2'])
#                 if not check_code(res[i]['_2']):
#                     res[i]['_2'] = get_file_code_by_lines(project_dir, file_path, res[i]['_3'], res[i]['_4'])
#         return res

