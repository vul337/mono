#include <iostream>
#include <vector>

using namespace std;

template<typename T>
class DataProcessor {
public:
    DataProcessor(T init) : data(init) {}

    // 运算符重载
    DataProcessor<T>& operator++() {
        data += 1;
        return *this;
    }

    // 模板成员函数
    template<typename U>
    void process(const U& input) {
        cout << "Processing: " << input << endl;
    }

private:
    T data;
};

int main() {
    // 基础类型与指针/引用
    int x = 5, y = 3;
    int* ptr = &x;
    int& ref = x;

    // 模板类实例化
    DataProcessor<int> processor(10);
    ++processor; 
    processor.process(3.14);  

    vector<string> names = {"Alice", "Bob"};
    int arr[5] = {1, 2, 3, 4, 5};

    return 0;
}

// {'file': './agent_utils/multi_static_utils/tree_sitter_tools/test/1.cpp', 
//     'value_info': [{'line': 29, 'name': 'x', 'type': 'int'}, 
//         {'line': 29, 'name': 'y', 'type': 'int'}, 
//         {'line': 30, 'name': 'ptr', 'type': 'int*'}, 
//         {'line': 31, 'name': 'ref', 'type': 'int&'}, 
//         {'line': 34, 'name': 'processor', 'type': 'DataProcessor<int>'}, 
//         {'line': 39, 'name': 'names', 'type': 'vector<string>'},
//         {'line': 40, 'name': 'arr', 'type': 'int[]'}], 
//    'func_info': [{'name': 'main', 'start_line': 27, 'end_line': 43, 'code': 'int main() {\n    // 基础类型与指针/引用\n    int x = 5, y = 3;\n    int* ptr = &x;\n    int& ref = x;\n\n    // 模板类实例化\n    DataProcessor<int> processor(10);\n    ++processor;  // 运算符调用\n    processor.process(3.14);  // 模板方法调用\n\n    // 容器与数组\n    vector<string> names = {"Alice", "Bob"};\n    int arr[5] = {1, 2, 3, 4, 5};\n\n    return 0;\n}'},
//         {'name': 'DataProcessor', 'start_line': 9, 'end_line': 9, 'code': 'DataProcessor(T init) : data(init) {}'},
//         {'name': 'process', 'start_line': 19, 'end_line': 21, 'code': 'void process(const U& input) {\n        cout << "Processing: " << input << endl;\n    }'}], 
//     'call_info': [{'name': 'processor.process', 'line': 36, 'params': ['3.14']}]}