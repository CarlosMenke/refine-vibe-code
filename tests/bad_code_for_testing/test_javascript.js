/**
 * Test file with JavaScript code containing various issues
 * for testing multi-language support
 */

// Hardcoded secrets (should be detected)
const API_KEY = "sk-1234567890abcdef1234567890abcdef12345678";
const DATABASE_PASSWORD = "super_secret_db_password_123!";
const JWT_SECRET = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// Bad ML code patterns
const tf = require('@tensorflow/tfjs');
const openai = require('openai');

// Dangerous: Loading model from untrusted source
async function loadDangerousModel() {
    const model = await tf.loadLayersModel('https://untrusted-site.com/malicious-model.json');
    return model;
}

// Dangerous: Executing AI-generated code
async function executeAIGeneratedCode() {
    const response = await openai.Completion.create({
        engine: "text-davinci-003",
        prompt: "Generate JavaScript code to calculate sum",
        max_tokens: 100
    });

    const code = response.choices[0].text;
    // CRITICAL: Direct execution of AI output
    eval(code); // Extremely dangerous!
}

// Poor comment quality
function addNumbers(a, b) {
    // This function adds two numbers together
    // It takes two parameters a and b
    // Returns the sum of a and b
    // This is very obvious and doesn't need comments
    return a + b;
}

// AI-generated naming patterns
function processUserDataFunction(userDataList) {
    const processedUserDataList = [];
    for (const userDataItem of userDataList) {
        const processedUserDataItem = userDataItem * 2;
        processedUserDataList.push(processedUserDataItem);
    }
    return processedUserDataList;
}

// SQL injection vulnerability
const mysql = require('mysql');

function vulnerableQuery(username, password) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: DATABASE_PASSWORD,
        database: 'test'
    });

    // HIGH severity - string concatenation in SQL
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    connection.query(query, (error, results) => {
        if (error) throw error;
        console.log(results);
    });

    connection.end();
}

// Edge cases and potential bugs
function processData(data) {
    // No null checks
    const result = data.map(item => item.value); // TypeError if data is null
    return result;
}

function divideNumbers(a, b) {
    // No division by zero check
    return a / b; // Infinity if b is 0
}

function accessArrayElement(arr, index) {
    // No bounds checking
    return arr[index]; // Undefined if index out of bounds
}

// Dangerous async patterns
async function dangerousAsyncOperation() {
    // No timeout
    const response = await fetch('https://slow-api.com/data');
    const data = await response.json();

    // No error handling
    return data;
}

// Inconsistent naming
function getUserData() {
    return "user data";
}

function fetchData() {
    return "fetched data";
}

function retrieveInfo() {
    return "info";
}

// Overly verbose comments
class Calculator {
    /**
     * A calculator class that performs basic arithmetic operations.
     * This class provides methods for addition, subtraction, multiplication, and division.
     * It is designed to handle basic mathematical calculations.
     * The class includes input validation and error handling.
     * All methods return numeric results.
     */
    constructor() {
        // Initialize the calculator
        // Set up internal state
        // Prepare for calculations
        this.ready = true;
    }

    /**
     * Add two numbers together.
     * This method takes two parameters and returns their sum.
     * The addition operation is performed using the + operator.
     * Both parameters should be numbers.
     * The result is also a number.
     */
    add(x, y) {
        // Perform addition
        // Use the + operator
        // Return the result
        return x + y;
    }
}

// Package/import issues
const unused_import = require('unused-package');
const another_unused = require('another-unused');

// Missing error handling in promises
function riskyPromiseOperation() {
    return fetch('https://api.example.com/data')
        .then(response => response.json())
        .then(data => {
            // Process data without validation
            return data.value * 2;
        });
        // No .catch() block!
}

// Dangerous use of eval
function dangerousEval(userInput) {
    // This is extremely dangerous
    return eval(userInput);
}

// Security issues
const crypto = require('crypto');

function insecurePasswordHash(password) {
    // Using MD5 - insecure!
    return crypto.createHash('md5').update(password).digest('hex');
}

// Global state issues
let globalCounter = 0;

function incrementGlobal() {
    globalCounter++;
    return globalCounter;
}

function resetGlobal() {
    globalCounter = 0;
}

// Race conditions
let sharedData = {};

function updateSharedData(key, value) {
    // No synchronization in JavaScript
    sharedData[key] = value;
}

// Memory leaks
function createMemoryLeak() {
    const data = [];
    setInterval(() => {
        data.push(new Array(1000).fill(0)); // Grows indefinitely
    }, 1000);
}

// Export everything
module.exports = {
    addNumbers,
    processUserDataFunction,
    vulnerableQuery,
    processData,
    divideNumbers,
    accessArrayElement,
    dangerousAsyncOperation,
    Calculator,
    riskyPromiseOperation,
    dangerousEval,
    insecurePasswordHash,
    incrementGlobal,
    resetGlobal,
    updateSharedData,
    createMemoryLeak
};
