import java.util.List;
import java.util.ArrayList;

public class Main<T> {
    // 泛型类 字段
    private List<T> dataList = new ArrayList<>();

    // 构造函数，返回值是空的，也没有 void，标签不一样
    public Main(T initialData) {
        dataList.add(initialData);
    }

    // 泛型
    public <U> void processData(U input) {
        System.out.println("Processing: " + input.toString());
    }

    // 链式 
    public Main<T> addData(T data) {
        dataList.add(data);
        return this;
    }

    public static void main(String[] args) {
        // 泛型 
        Main<String> processor = new Main<>("Initial");
        processor.addData("NewData")  // 链式 调用
                .processData(100);    // 泛型 方法调用

        // 容器与注解
        @SuppressWarnings("unchecked")
        List<Integer> numbers = new ArrayList();
        numbers.add(42);
    }
}


{'file': './agent_utils/multi_static_utils/tree_sitter_tools/test/1.java', 
'value_info':
 [{'line': 31, 'name': 'numbers', 'type': 'List[Integer]'},
 {'line': 26, 'name': 'processor', 'type': 'Main[String]'}], 

 'func_info': 
 [{'name': 'main', 'start_line': 24, 'end_line': 34, 'code': 'public static void main(String[] args) {\n        // 泛型 \n        Main<String> processor = new Main<>("Initial");\n        processor.addData("NewData")  // 链式 调用\n               // .processData(100);    // 泛型 方法调用\n\n        // 容器与注解\n        @SuppressWarnings("unchecked")\n        // List<Integer> numbers = new ArrayList();\n        numbers.add(42);\n    }'}, 
 {'name': 'addData', 'start_line': 19, 'end_line': 22, 'code': 'public Main<T> addData(T data) {\n        dataList.add(data);\n        return this;\n    }'},
  {'name': 'processData', 'start_line': 14, 'end_line': 16, 'code': 'public <U> void processData(U input) {\n        System.out.println("Processing: " + input.toString());\n    }'}, 
  {'name': 'Main', 'start_line': 9, 'end_line': 11, 'code': 'public Main(T initialData) {\n        dataList.add(initialData);\n    }'}], 
  
  'call_info': 
  [{'name': 'add', 'line': 33, 'params': ['42']}, 
  {'name': 'processData', 'line': 27, 'params': ['100']}, 
  {'name': 'addData', 'line': 27, 'params': ['"NewData"']}, 
  {'name': 'add', 'line': 20, 'params': ['data']}, 
  {'name': 'println', 'line': 15, 'params': ['"Processing: " + input.toString()']}, 
  {'name': 'toString', 'line': 15, 'params': []},
   {'name': 'add', 'line': 10, 'params': ['initialData']}]}
