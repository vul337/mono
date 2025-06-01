package com.example.utils;

public class MathUtils {
  
    public static int add(int a, int b) {
        return a + b;
    }


    public static int factorial(int n) {
        if (n <= 1) return 1;
        return n * factorial(n - 1);
    }
}