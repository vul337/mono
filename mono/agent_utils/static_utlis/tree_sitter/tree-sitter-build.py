from tree_sitter import Language


Language.build_library(
    "./build/c-cpp-java.so",  
    [
        "./tree-sitter-c",
        "./tree-sitter-cpp",
        "./tree-sitter-java"
    ]
)