package com.example.main;
import static com.example.utils.MathUtils.factorial;  

public class DataProcessor {
    public void process() {
        int result = factorial(5);                   // 6 (MathUtils.factorial)
        System.out.println("Factorial: " + result);
        
        // 跨文件调用 StringUtils,明显的
        String str = com.example.utils.StringUtils.capitalize("data");  //  10
        System.out.println("Processed: " + str);
    }
}