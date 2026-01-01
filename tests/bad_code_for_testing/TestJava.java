/**
 * Test file with Java code containing various issues
 * for testing multi-language support
 */

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class TestJava {

    // Hardcoded secrets (should be detected)
    private static final String API_KEY = "sk-1234567890abcdef1234567890abcdef12345678";
    private static final String DATABASE_PASSWORD = "super_secret_db_password_123!";
    private static final String JWT_SECRET = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

    // Database connection parameters with secrets
    private static final String DB_URL = "jdbc:postgresql://localhost:5432/test";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "hardcoded_db_password_123!";

    /**
     * Function with poor comment quality.
     * This function adds two numbers together.
     * It takes two parameters a and b.
     * Returns the sum of a and b.
     * This is very obvious and doesn't need such verbose comments.
     */
    public int addNumbers(int a, int b) {
        // Add a and b together
        // Return the result
        return a + b;
    }

    /**
     * AI-generated naming patterns
     */
    public List<Integer> processUserDataFunction(List<Integer> userDataList) {
        List<Integer> processedUserDataList = new ArrayList<>();
        for (Integer userDataItem : userDataList) {
            Integer processedUserDataItem = userDataItem * 2;
            processedUserDataList.add(processedUserDataItem);
        }
        return processedUserDataList;
    }

    /**
     * SQL injection vulnerability
     */
    public List<Map<String, Object>> vulnerableQuery(String username, String password) {
        List<Map<String, Object>> results = new ArrayList<>();

        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // HIGH severity - string concatenation in SQL
            String query = "SELECT * FROM users WHERE username = '" + username +
                          "' AND password = '" + password + "'";

            PreparedStatement stmt = conn.prepareStatement(query); // Still vulnerable!
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("username", rs.getString("username"));
                results.add(row);
            }

            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return results;
    }

    /**
     * Edge cases and potential bugs
     */
    public int divideNumbers(int a, int b) {
        // No division by zero check
        return a / b; // ArithmeticException if b is 0
    }

    public String accessListElement(List<String> list, int index) {
        // No bounds checking
        return list.get(index); // IndexOutOfBoundsException if index invalid
    }

    public String processData(Map<String, Object> data) {
        // No null checks
        return (String) data.get("name"); // ClassCastException possible
    }

    /**
     * Dangerous async patterns
     */
    public CompletableFuture<String> dangerousAsyncOperation() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://slow-api.com/data"))
            .build();

        // No timeout specified
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenApply(HttpResponse::body);
    }

    /**
     * Inconsistent naming conventions
     */
    public String getUserData() {
        return "user data";
    }

    public String fetchData() {
        return "fetched data";
    }

    public String retrieveInfo() {
        return "info";
    }

    /**
     * Overly verbose comments
     */
    public class Calculator {
        /**
         * A calculator class that performs basic arithmetic operations.
         * This class provides methods for addition, subtraction, multiplication, and division.
         * It is designed to handle basic mathematical calculations.
         * The class includes input validation and error handling.
         * All methods return numeric results.
         * The class is thread-safe for single-threaded usage.
         * It implements the basic calculator interface.
         * The implementation is efficient and optimized.
         */

        private boolean initialized;

        public Calculator() {
            // Initialize the calculator
            // Set up internal state
            // Prepare for calculations
            // Mark as ready
            this.initialized = true;
        }

        /**
         * Add two numbers together.
         * This method takes two parameters x and y.
         * It performs addition operation on the parameters.
         * The result is the sum of x and y.
         * Both parameters should be integers.
         * The method returns an integer result.
         * No overflow checking is performed.
         * The operation is commutative.
         * The method is public and can be called from outside.
         */
        public int add(int x, int y) {
            // Perform addition
            // Use the + operator
            // Return the result
            // This is a simple operation
            return x + y;
        }
    }

    /**
     * Package/import issues
     */
    // Unused imports (these should be flagged)
    // import java.util.Set;  // Not used
    // import java.util.Queue;  // Not used
    // import java.io.BufferedReader;  // Not used

    /**
     * Missing error handling
     */
    public String readFile(String filename) {
        try {
            return new String(Files.readAllBytes(Paths.get(filename)));
        } catch (IOException e) {
            // Generic error handling
            return null;
        }
    }

    /**
     * Security issues
     */
    public String insecurePasswordHash(String password) {
        // Using insecure hashing
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Global state issues
     */
    private static int globalCounter = 0;

    public static synchronized int incrementGlobal() {
        globalCounter++;
        return globalCounter;
    }

    public static void resetGlobal() {
        globalCounter = 0;
    }

    /**
     * Race conditions (in non-synchronized methods)
     */
    private Map<String, Object> sharedData = new HashMap<>();

    public void updateSharedData(String key, Object value) {
        // No synchronization - race condition possible
        sharedData.put(key, value);
    }

    public Object getSharedData(String key) {
        // No synchronization
        return sharedData.get(key);
    }

    /**
     * Memory leaks
     */
    private List<byte[]> memoryHog = new ArrayList<>();

    public void createMemoryLeak() {
        // Continuously add large objects
        for (int i = 0; i < 1000; i++) {
            memoryHog.add(new byte[1024 * 1024]); // 1MB each
        }
    }

    /**
     * Exception handling issues
     */
    public void riskyOperation() throws Exception {
        try {
            // Risky operation
            Thread.sleep(1000);
            if (Math.random() > 0.5) {
                throw new RuntimeException("Random failure");
            }
        } catch (Exception e) {
            // Generic catch - might hide important exceptions
            System.out.println("Error occurred: " + e.getMessage());
            throw e; // Re-throw
        }
    }

    /**
     * Resource management issues
     */
    public void resourceLeak() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            // Do something with connection
            System.out.println("Connected to database");
            // Forgot to close connection!
        } catch (SQLException e) {
            e.printStackTrace();
        }
        // Connection not closed - resource leak!
    }

    /**
     * Threading issues
     */
    public void threadingProblem() {
        Thread thread = new Thread(() -> {
            try {
                Thread.sleep(5000); // Long running operation
                System.out.println("Thread completed");
            } catch (InterruptedException e) {
                // Handle interruption
                Thread.currentThread().interrupt();
            }
        });

        thread.start();
        // No join() - thread may not complete before main thread exits
    }

    /**
     * AI logic simulation (conceptual)
     */
    public String simulateAIOperation(String input) {
        // Simulate calling an AI service
        if (input.contains("code")) {
            // Dangerous: would execute AI-generated code
            // eval(input); // DON'T DO THIS
            return "Would execute AI-generated code";
        }
        return "Safe operation";
    }

    /**
     * Main method for testing
     */
    public static void main(String[] args) {
        TestJava test = new TestJava();

        // Test various methods
        System.out.println("Sum: " + test.addNumbers(5, 3));
        System.out.println("Processed: " + test.processUserDataFunction(List.of(1, 2, 3)));

        // Risky operations
        try {
            System.out.println("Division: " + test.divideNumbers(10, 0)); // Will throw exception
        } catch (ArithmeticException e) {
            System.out.println("Caught division by zero: " + e.getMessage());
        }
    }
}
