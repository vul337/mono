from tree_sitter import Node
from typing import List, Optional, Dict
from func_file_utils import LanguageConfig, UniversalCodeAnalyzer, Language
from project_utils import find_call_init_in_project, find_func_call_info_in_project
from pathlib import Path


def java_function_name_extractor(node: Node) -> Optional[str]:
    if node.type == 'constructor_declaration':
        class_decl = node.parent.parent  # constructor -> class_body -> class_declaration
        if class_decl and class_decl.type == 'class_declaration':
            class_name_node = class_decl.child_by_field_name('name')
            method_name_node = node.child_by_field_name('name')
            if class_name_node and method_name_node:
                class_name = class_name_node.text.decode().strip()
                method_name = method_name_node.text.decode().strip()
                if class_name == method_name:
                    return method_name


    elif node.type == 'method_declaration':
        name_node = node.child_by_field_name('name')
        return name_node.text.decode().strip() if name_node else None

    return None

def java_call_resolver(node: Node) -> Optional[str]:
    # keep system library methods, such as System.out.println
    if node.type != 'method_invocation':
        return None
    
    method_select = node.child_by_field_name('method_select')
    if method_select and method_select.type == 'identifier':
        return method_select.text.decode()
    
    return node.child_by_field_name('name').text.decode()

def java_variable_extractor(node: Node, language: Language) -> Optional[List[Dict]]:
    if node.type != 'local_variable_declaration':
        return None

    query = language.query("""
        (local_variable_declaration
            type: (_) @type
            declarator: (variable_declarator name: (identifier) @name)
        )
    """)

    variables = []
    type_text = ""
    for capture, capture_name in query.captures(node):
        if capture_name == 'type':
            type_text = capture.text.decode().replace('<', '[').replace('>', ']')
        elif capture_name == 'name':
            variables.append({
                "name": capture.text.decode(),
                "type": type_text
            })
    
    return variables


library_functions = [
    "System.out.println",
    "System.err.println",
    "System.out.print",
    "System.err.print",
    "System.exit",
    "System.getenv",
    "System.getProperties",
    "System.getProperty",
    "System.setProperties",
    "System.setProperty",   
    "System.arraycopy",
    "System.clearProperty",
    "System.console",
    "System.currentTimeMillis",
    "System.nanoTime",
    "System"
]




java_config = LanguageConfig(
    name="java",
    library_path="/tree_sitter/build/c-cpp-java.so", 
    file_patterns=["*.java"],
    node_types={
        "function_def":  ["constructor_declaration", "method_declaration"],
        "call_expr": "method_invocation",
        "variable_declaration": "local_variable_declaration"
    },
    library_functions=library_functions,
    function_name_extractor=java_function_name_extractor,
    call_resolver=java_call_resolver,
    variable_extractor=lambda n: java_variable_extractor(n, java_config.language),
    call_params_extractor=lambda n: [
        arg.text.decode()
        for arg in n.child_by_field_name('arguments').children
        if arg.type not in ('(', ')', ',')
    ]
)

# def print_java_tree(file):
#     from tree_sitter import Parser, Language
#     JAVA_LANGUAGE = Language('../tree_sitter/build/c-cpp-java.so', 'java')
#     parser = Parser()
#     parser.set_language(JAVA_LANGUAGE)
#     with open(file, 'rb') as f:
#         tree = parser.parse(f.read())
    
#     def print_node(node, indent=''):
#         print(f"{indent}{node.type} [{node.start_point}-{node.end_point}]")
#         for child in node.children:
#             print_node(child, indent + '  ')
    
#     print_node(tree.root_node)





def java_analyzer_context(file_path: Path, start_line: int, end_line: int, java_config=java_config):
    analyzer = UniversalCodeAnalyzer(java_config)
    return analyzer.analyze_context(file_path, start_line, end_line)


def java_find_call_init_in_project(project_dir: Path, current_file: Path, line: int, call_func_name: str, lang_config: LanguageConfig = java_config):
    return find_call_init_in_project(
        project_dir=project_dir,
        current_file=current_file,
        line=line,
        call_func_name=call_func_name,
        lang_config=lang_config
    )

def java_find_func_call_info_in_project(project_dir: Path, file_path: Path, func_name: str, lang_config: LanguageConfig = java_config):
    return find_func_call_info_in_project(
        file_path=file_path,
        project_dir=project_dir,
        func_name=func_name,
        lang_config=lang_config
    )



def test1():
    analyzer = UniversalCodeAnalyzer(java_config)
    context = analyzer.analyze_context(Path(file), 1, 100)
    print(context)

def test2():
    
    result = find_call_init_in_project(
        project_dir=project_dir,
        current_file=Path(file),
        line=10,
        call_func_name='capitalize',
        lang_config=java_config
    )
    print(result)
# 'start_line': 5, 'end_line': 10, 
# 'code': 'public static String capitalize(String input) {\n        if (input == null || input.isEmpty()) {\n            return input;\n        }\n        return input.substring(0, 1).toUpperCase() + input.substring(1);\n    }'}]



def test3():
    project_dir =""
    file = ""# 131 , 158
    analyzer = UniversalCodeAnalyzer(java_config)
    context = analyzer.analyze_context(Path(file), 131, 158)
    print(context)
    # input()
    
    result = find_func_call_info_in_project(
        project_dir=project_dir,
        file_path=Path(file),
        func_name='Criteria',
        lang_config=java_config
    )

    print(result)



if __name__ == '__main__':
    test3()

    # print_java_tree(file)