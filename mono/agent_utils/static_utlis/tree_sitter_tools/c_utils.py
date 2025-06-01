from tree_sitter import Node
from typing import List, Optional, Dict
from func_file_utils import LanguageConfig, UniversalCodeAnalyzer, Language
from project_utils import find_call_init_in_project, find_func_call_info_in_project
from pathlib import Path


def c_function_name_extractor(node: Node) -> Optional[str]:
    if node.type not in ('function_definition', 'struct_specifier'):
        return None

    if node.type == 'struct_specifier': # struct
        name_node = node.child_by_field_name('name')
        if name_node and name_node.type == 'type_identifier':
            return name_node.text.decode().strip()
        return None  

    has_body = any(child.type == 'compound_statement' for child in node.children)
    if not has_body:
        return None

    declarator = node.child_by_field_name('declarator')
    while declarator and declarator.type not in ('function_declarator', 'identifier'):
        declarator = declarator.child_by_field_name('declarator')

    if declarator and declarator.type == 'function_declarator':
        name_node = declarator.child_by_field_name('declarator')
        if name_node and name_node.type == 'identifier':
            return name_node.text.decode().strip()
    
    return None


def c_call_resolver(node: Node) -> Optional[str]:
    function_node = node.child_by_field_name('function')
    if function_node and function_node.type == 'identifier':
        return function_node.text.decode()
    return None


def c_variable_extractor(node: Node, language: Language) -> Optional[List[Dict]]:
    if node.type != 'declaration':
        return None

    # get all variables (tpye and name)
    query = language.query("""
        (declaration
            type: [
                (primitive_type)
                (type_identifier)
                (struct_specifier)
                (enum_specifier)
                (union_specifier)
            ] @base_type
            declarator: [
                (init_declarator declarator: (_) @var_declarator)
                (_) @var_declarator
            ]
        )
    """)

    type_text = ""
    variables = []
    processed_vars = set()  # use to avoid duplicate variables
    captures = query.captures(node)

    for obj, capture_name in captures:
        if capture_name == 'base_type':
            type_text = obj.text.decode()
        elif capture_name == 'var_declarator':
            # use stack to avoid recursion
            stack = [obj]
            var_name = ""
            is_ptr = False
            is_arr = False

            while stack:
                current = stack.pop()
                if current.type == 'identifier':
                    var_name = current.text.decode()
                elif current.type == 'pointer_declarator':
                    is_ptr = True
                elif current.type == 'array_declarator':
                    is_arr = True
                stack.extend(current.children)

            final_type = type_text
            if is_ptr:
                final_type += '*'  # ptr type
            if is_arr:
                final_type += '[]'  # array type

            # 
            if var_name and var_name not in processed_vars:
                processed_vars.add(var_name)
                variables.append({
                    "name": var_name,
                    "type": final_type.strip()
                })

    return variables

library_functions = [
    "printf",
    "scanf",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "rewind",
    "fgetpos",
    "fsetpos",
    "feof",
    "ferror",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strcmp",
    "strncmp",
    "strchr",
    "strrchr",
    "strstr",
    "strlen",
    "strerror",
    "strdup",
    "strtok",
    "strtok_r",
    "strcoll",
    "strxfrm",
    "strcspn",
    "strpbrk",
    "strspn",
    "strerror",
    "strsignal",
    "strerror_r",
    "strncasecmp",
    "strcasecmp",
    "strsep",
    "strnlen",
    "strndup",
    "strnlen",
    "strnstr",
    "strsignal"
]

c_config = LanguageConfig(
    name="c",
    library_path="/tree_sitter/build/c-cpp-java.so",
    file_patterns=["*.c", "*.h"],
    node_types={
        "function_def": "function_definition",
        "call_expr": "call_expression",
        "variable_declaration": "declaration"
    },
    library_functions=library_functions,
    function_name_extractor=c_function_name_extractor,
    call_resolver=c_call_resolver,
    variable_extractor=lambda n: c_variable_extractor(n, c_config.language), 
    call_params_extractor=lambda n: [
        arg.text.decode()
        for arg in n.child_by_field_name('arguments').children
        if arg.type not in ('(', ')', ',')
    ]
)

def c_analyzer_context(file_path: Path, start_line: int, end_line: int, c_config=c_config) -> Optional[Dict]:    
    analyzer = UniversalCodeAnalyzer(c_config)
    return analyzer.analyze_context(file_path, start_line, end_line)


def c_find_call_init_in_project(project_dir: Path, file_path: Path, line: int, func_name: str, lang_config: LanguageConfig = c_config):
    return find_call_init_in_project(
        project_dir=project_dir,
        current_file=file_path,
        line=line,
        call_func_name=func_name,
        lang_config=lang_config
    )

def c_find_func_call_info_in_project(project_dir: Path, file_path: Path, func_name: str, lang_config: LanguageConfig = c_config):
    return find_func_call_info_in_project(
        file_path=file_path,
        project_dir=project_dir,
        func_name=func_name,
        lang_config=lang_config
    )



def test1():
    file = Path("//test/my_test/src-main.c")
    print(c_analyzer_context(file, 5, 10))

def test2():
    project_dir = Path('/tree_sitter_tools/test/c_project')
    file = project_dir / 'main.c'

    result = find_call_init_in_project(
    project_dir=project_dir,
    current_file=Path(file),
    line=10,
    call_func_name='add',
    lang_config=c_config
    )
    print(result)

def test3():
    project_dir = Path('multi_static_utils/tree_sitter_tools/test/c_project')
    result = find_func_call_info_in_project(
        file_path="test/c_project/main.c",
        project_dir=project_dir,
        func_name="main",
        lang_config=c_config
    )
    
    
    print(result)

if __name__ == "__main__":
    test1()