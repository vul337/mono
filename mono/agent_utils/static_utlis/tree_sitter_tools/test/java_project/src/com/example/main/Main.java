package com.example.main;
import com.example.utils.StringUtils;
import com.example.utils.MathUtils;

public class Main {
    public static void main(String[] args) {
        String name = "alice";
        String capitalized = StringUtils.capitalize(name);  //  8
        System.out.println("Capitalized: " + capitalized);


        int sum = MathUtils.add(3, 5);                     // 12
        System.out.println("Sum: " + sum);
    }
}