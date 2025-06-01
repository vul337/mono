from tree_sitter import Node
from typing import List, Optional, Dict
from func_file_utils import LanguageConfig, UniversalCodeAnalyzer, Language
from project_utils import find_call_init_in_project, find_func_call_info_in_project
from pathlib import Path


def cpp_function_name_extractor(node: Node) -> Optional[str]:
    if node.type != 'function_definition':
        return None

    # eg. class_name::class_name() -> class_name
    if node.parent and node.parent.type == 'class_specifier':
        class_name = node.parent.child_by_field_name('name').text.decode()
        return class_name

    # eg. int add(int a, int b) -> add
    # eg. operator<< -> operator reload
    declarator = node.child_by_field_name('declarator')
    while declarator and declarator.type not in ('function_declarator', 'operator_cast'):
        declarator = declarator.child_by_field_name('declarator')

    if declarator and declarator.type == 'function_declarator':
        name_node = declarator.child_by_field_name('declarator')
        if name_node and name_node.type == 'identifier':
            return name_node.text.decode()
    elif declarator and declarator.type == 'operator_cast':
        return f"operator {declarator.text.decode()}"
    
    return None

def cpp_call_resolver(node: Node) -> Optional[str]:
    function_node = node.child_by_field_name('function')
    if not function_node:
        return None
    
    # function_node -> template_function -> function
    if function_node.type == 'template_function':
        base_func = function_node.child_by_field_name('function')
        if base_func and base_func.type == 'identifier':
            return base_func.text.decode()
    
    # eg operator<<）
    elif function_node.type == 'operator_name':
        return f"operator{function_node.text.decode()}"
    
    return function_node.text.decode()

def cpp_variable_extractor(node: Node, language: Language) -> Optional[List[Dict]]:
    if node.type not in ('declaration', 'field_declaration'):
        return None

    # eg. int* a, int& b, int c[], auto d
    query = language.query("""
        (declaration
            type: [
                (primitive_type) 
                (type_identifier)
                (template_type)
                (auto)
            ] @type
            declarator: (init_declarator declarator: (_) @declarator)
        )
        (field_declaration
            type: _ @type
            declarator: _ @declarator
        )
    """)

    variables = []
    processed = set()
    type_text = ""

    for capture, capture_name in query.captures(node):
        if capture_name == 'type':
            type_text = capture.text.decode()
        elif capture_name == 'declarator':
           
            var_name = ""
            ptr_suffix = ""
            ref_suffix = ""
            arr_suffix = ""

            # stack to avoid recursion
            stack = [capture]
            while stack:
                current = stack.pop()
                if current.type == 'identifier':
                    var_name = current.text.decode()
                elif current.type == 'pointer_declarator':
                    ptr_suffix += '*'
                elif current.type == 'reference_declarator':
                    ref_suffix += '&'
                elif current.type == 'array_declarator':
                    arr_suffix += '[]'
                stack.extend(current.children)

        
            final_type = f"{type_text}{ptr_suffix}{ref_suffix}{arr_suffix}".strip()

            if var_name and var_name not in processed:
                variables.append({
                    "name": var_name,
                    "type": final_type
                })
                processed.add(var_name)

    return variables

library_functions = [
    "printf",
    "scanf",
    "cin",
    "cout",
    "cerr",
    "clog",
    "getline",
    "getchar",
    "putchar",
    "putchar",
    "puts"
]


cpp_config = LanguageConfig(
    name="cpp",
    library_path="./agent_utils/multi_static_utils/tree_sitter/build/c-cpp-java.so",
    file_patterns=["*.cpp", "*.hpp", "*.h"],
    node_types={
        "function_def": ['function_definition', 'struct_specifier'],
        "call_expr": "call_expression",
        "variable_declaration": "declaration"
    },
    library_functions=library_functions,
    function_name_extractor=cpp_function_name_extractor,
    call_resolver=cpp_call_resolver,
    variable_extractor=lambda n: cpp_variable_extractor(n, cpp_config.language),
    call_params_extractor=lambda n: [
        arg.text.decode() 
        for arg in n.child_by_field_name('arguments').children
        if arg.type not in ('(', ')', ',', 'template_argument_list')
    ]
)


def cpp_analyzer_context(file_path: Path, start_line: int, end_line: int, cpp_config=cpp_config):
    analyzer = UniversalCodeAnalyzer(cpp_config)
    return analyzer.analyze_context(file_path, start_line, end_line)


def cpp_find_call_init_in_project(project_dir: Path, file_path: Path, line: int, func_name: str, lang_config: LanguageConfig = cpp_config):
    return find_call_init_in_project(
        project_dir=project_dir,
        current_file=file_path,
        line=line,
        call_func_name=func_name,
        lang_config=lang_config
    )

def cpp_find_func_call_info_in_project(project_dir: Path, file_path: Path,  func_name: str, lang_config: LanguageConfig = cpp_config):
    return find_func_call_info_in_project(
        file_path=file_path,
        project_dir=project_dir,
        func_name=func_name,
        lang_config=lang_config
    )




def test1():
    file = "/tree_sitter_tools/test/1.cpp"
    analyzer = UniversalCodeAnalyzer(cpp_config)
    result = analyzer.analyze_context(Path(file), 7, 100)
    print(result)



def test2():
    project_dir = Path("/tree_sitter_tools/test/cpp_project")
    file = "/tree_sitter_tools/test/cpp_project/src/main.cpp"

    result = find_call_init_in_project(
        project_dir=project_dir,
        current_file=Path(file),
        line=4,
        call_func_name='add',
        lang_config=cpp_config
    )
    print(result)


# def test3():



if __name__ == "__main__":
    test2()
    
