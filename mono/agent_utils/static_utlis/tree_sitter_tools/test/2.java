public class Main<T> {
    public Main(T initialData) {
        dataList.add(initialData);
    }
}

public <U> void processData(U input) {
    System.out.println("Processing: " + input.toString());
}