"""
Comprehensive stress test file for comment quality checker.
Tests various comment and docstring patterns that should be detected as poor quality.
"""

# ==========================================
# REDUNDANT COMMENTS (SHOULD BE FLAGGED)
# ==========================================

def add_numbers(a, b):
    """
    This function adds two numbers together.
    It takes two parameters, a and b, and returns their sum.
    This is a very basic arithmetic operation.
    """
    # Add a and b together
    result = a + b
    # Return the result
    return result

def multiply_numbers(x, y):
    """
    This function multiplies two numbers.
    It performs multiplication on the input parameters.
    The result is the product of the two numbers.
    """
    # Multiply x by y
    product = x * y
    # Return the product
    return product

def calculate_average(numbers):
    """
    This function calculates the average of a list of numbers.
    It takes a list as input and returns the average value.
    The average is computed by summing all numbers and dividing by the count.
    """
    # Initialize sum to zero
    total = 0
    # Loop through each number in the list
    for num in numbers:
        # Add the current number to the total
        total += num
    # Calculate the average
    average = total / len(numbers)
    # Return the average
    return average

# ==========================================
# USELESS DOCSTRINGS (SHOULD BE FLAGGED)
# ==========================================

def process_data(data):
    """
    Process the data.
    This function processes data.
    It takes data as input and processes it.
    The function returns the processed data.
    """
    # Process the data
    processed = data * 2
    # Return processed data
    return processed

def validate_input(input_value):
    """
    Validate the input.
    This function validates input.
    It checks if the input is valid.
    Returns True if valid, False otherwise.
    """
    # Check if input is valid
    if input_value is not None:
        # Return True
        return True
    else:
        # Return False
        return False

def transform_data(data):
    """
    Transform the data.
    This function transforms data.
    It applies transformations to the input data.
    Returns the transformed data.
    """
    # Transform the data
    transformed = [x.upper() for x in data]
    # Return transformed data
    return transformed

# ==========================================
# OVERLY VERBOSE DOCSTRINGS (SHOULD BE FLAGGED)
# ==========================================

def simple_validation(user_input):
    """
    This function is designed to validate user input that is passed to it as a parameter.

    The function takes a single parameter called user_input which represents the input
    that has been provided by the user in the application. This input could be any type
    of data that needs to be validated according to certain business rules and requirements.

    The validation process involves several steps and checks to ensure that the input
    meets all the necessary criteria and standards. First, the function checks if the
    input exists and is not None. Then it verifies that the input is of the correct type,
    which in this case should be a string. After that, it checks the length of the input
    to make sure it falls within acceptable limits.

    If all the validation checks pass successfully, the function will return a boolean
    value of True, indicating that the input is valid and can be safely used in the
    application. However, if any of the validation checks fail, the function will return
    False, which means the input did not meet the required standards and should not be
    used further in the processing pipeline.

    This validation is important for maintaining data integrity and preventing potential
    security issues that could arise from malformed or malicious input data. The function
    is designed to be robust and handle various edge cases that might occur during the
    validation process.

    Args:
        user_input: The input provided by the user that needs to be validated

    Returns:
        bool: A boolean value indicating whether the input is valid (True) or not (False)

    Raises:
        No exceptions are raised by this function under normal circumstances.
    """
    if user_input is None:
        return False
    if not isinstance(user_input, str):
        return False
    if len(user_input.strip()) == 0:
        return False
    return True

# ==========================================
# ROBOTIC/GENERIC DOCSTRINGS (SHOULD BE FLAGGED)
# ==========================================

def authenticate_user(username, password):
    """
    This function authenticates a user.

    Args:
        username: The username
        password: The password

    Returns:
        Authentication result
    """
    # Authenticate user
    return username == "admin" and password == "password"

def save_file(filename, content):
    """
    This function saves a file.

    Args:
        filename: The name of the file
        content: The content to save

    Returns:
        Save result
    """
    # Save the file
    with open(filename, 'w') as f:
        f.write(content)
    return True

def load_configuration(config_path):
    """
    This function loads configuration.

    Args:
        config_path: The path to the configuration file

    Returns:
        Configuration data
    """
    # Load configuration
    import json
    with open(config_path, 'r') as f:
        return json.load(f)

# ==========================================
# CONTRADICTORY COMMENTS (SHOULD BE FLAGGED)
# ==========================================

def divide_numbers(a, b):
    """
    This function divides two numbers.
    It always returns a positive result.
    """
    # This will crash if b is zero
    result = a / b  # This can cause ZeroDivisionError
    return result

def get_user_data(user_id):
    """
    This function retrieves user data from the database.
    It always returns valid user data.
    """
    # This could return None if user doesn't exist
    users = {"1": {"name": "John"}, "2": {"name": "Jane"}}
    return users.get(user_id)  # Could return None

def process_payment(amount, card_number):
    """
    This function processes a payment securely.
    All payment data is encrypted and safe.
    """
    # Storing card number in plain text - NOT SECURE
    payment_data = {
        "amount": amount,
        "card": card_number  # Plain text storage!
    }
    return payment_data

# ==========================================
# OUTDATED COMMENTS (SHOULD BE FLAGGED)
# ==========================================

def old_api_call():
    """
    This function calls the v1 API endpoint.
    It uses the old authentication method.
    """
    # This code was written in 2019
    # Still using the deprecated API
    import requests
    response = requests.get("https://api.example.com/v1/data")
    return response.json()

def legacy_function():
    """
    This is the new implementation using modern practices.
    """
    # TODO: Refactor this legacy code
    # This function is from the old codebase
    # Uses outdated patterns
    result = []
    for i in range(10):
        # Old way of doing things
        result.append(i * 2)
    return result

# ==========================================
# AI-GENERATED COMMENT PATTERNS (SHOULD BE FLAGGED)
# ==========================================

def calculate_total(items):
    """
    This function takes a list of items and calculates the total value.

    The function iterates through each item in the provided list, extracts
    the price attribute from each item, and accumulates these prices to
    compute the total value. The function ensures that all items have a
    valid price before including them in the calculation.

    Parameters:
    items (list): A list of item objects, each containing a price attribute

    Returns:
    float: The total calculated value of all items
    """
    # Initialize the total variable to zero
    total = 0.0

    # Iterate through each item in the items list
    for item in items:
        # Check if the item has a price attribute
        if hasattr(item, 'price'):
            # Add the price of the current item to the total
            total += item.price

    # Return the calculated total
    return total

def data_processor(input_data):
    """
    This function is responsible for processing the input data.

    The function performs several operations on the input data, including
    validation, transformation, and formatting. It ensures that the data
    meets certain criteria before proceeding with the processing steps.
    The function handles various data types and converts them to a
    standardized format for further use in the application.

    Args:
        input_data: The data to be processed

    Returns:
        Processed data in the required format
    """
    # Validate the input data
    if not input_data:
        # Return empty result if no data
        return []

    # Process each item in the data
    processed = []
    for item in input_data:
        # Transform the item
        transformed = str(item).upper()
        # Add to processed list
        processed.append(transformed)

    # Return the processed data
    return processed

# ==========================================
# USELESS INLINE COMMENTS (SHOULD BE FLAGGED)
# ==========================================

def fibonacci(n):
    """
    Calculate the nth Fibonacci number.
    """
    # Set a to 0
    a = 0
    # Set b to 1
    b = 1
    # Loop n times
    for i in range(n):
        # Calculate next number
        temp = a + b
        # Update a
        a = b
        # Update b
        b = temp
    # Return result
    return a

def is_even(number):
    """
    Check if a number is even.
    """
    # Calculate remainder when divided by 2
    remainder = number % 2
    # Check if remainder is 0
    if remainder == 0:
        # Return True if even
        return True
    else:
        # Return False if odd
        return False

# ==========================================
# TEMPLATE-BASED DOCSTRINGS (SHOULD BE FLAGGED)
# ==========================================

def api_endpoint_handler(request):
    """
    Handle API endpoint requests.

    This view function handles incoming HTTP requests for the API endpoint.
    It processes the request data, performs necessary validations, and returns
    an appropriate response based on the request parameters.

    Args:
        request: The HTTP request object containing request data

    Returns:
        HTTP response with appropriate status code and data
    """
    # Extract data from request
    data = request.get_json()

    # Validate request data
    if not data:
        return {"error": "No data provided"}, 400

    # Process the request
    result = {"message": "Request processed", "data": data}

    return result, 200

def database_query_executor(query, params):
    """
    Execute database queries with parameters.

    This function provides a safe way to execute database queries by using
    parameterized queries to prevent SQL injection attacks. It establishes
    a connection to the database, executes the query with the provided parameters,
    and returns the results.

    Args:
        query (str): The SQL query to execute
        params (tuple): Parameters to bind to the query

    Returns:
        List of query results
    """
    import sqlite3

    # Connect to database
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Execute query with parameters
    cursor.execute(query, params)
    results = cursor.fetchall()

    # Close connection
    conn.close()

    return results

# ==========================================
# COPY-PASTE DOCSTRINGS (SHOULD BE FLAGGED)
# ==========================================

def file_reader(file_path):
    """
    Read data from a file.

    This function opens a file at the specified path and reads its contents.
    It handles file opening errors and returns the file contents as a string.
    The function ensures that the file is properly closed after reading.

    Args:
        file_path (str): The path to the file to read

    Returns:
        str: The contents of the file

    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If there are insufficient permissions to read the file
    """
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except PermissionError:
        raise PermissionError(f"Permission denied: {file_path}")

def file_writer(file_path, content):
    """
    Write data to a file.

    This function opens a file at the specified path and writes content to it.
    It handles file opening errors and ensures that the file is properly closed
    after writing. The function creates the file if it doesn't exist.

    Args:
        file_path (str): The path to the file to write
        content (str): The content to write to the file

    Raises:
        PermissionError: If there are insufficient permissions to write to the file
    """
    try:
        with open(file_path, 'w') as file:
            file.write(content)
    except PermissionError:
        raise PermissionError(f"Permission denied: {file_path}")

def data_validator(data):
    """
    Validate data according to business rules.

    This function validates input data against predefined business rules and
    constraints. It checks data types, ranges, and formats to ensure data
    integrity. The function returns validation results with detailed error
    messages for any validation failures.

    Args:
        data: The data to validate

    Returns:
        dict: Validation results with success status and error messages
    """
    errors = []

    if not isinstance(data, dict):
        errors.append("Data must be a dictionary")

    if 'name' not in data:
        errors.append("Name field is required")

    if 'age' in data and not isinstance(data['age'], int):
        errors.append("Age must be an integer")

    return {
        "valid": len(errors) == 0,
        "errors": errors
    }

# ==========================================
# MISLEADING DOCSTRINGS (SHOULD BE FLAGGED)
# ==========================================

def risky_operation():
    """
    This function performs a safe operation.
    It includes proper error handling and validation.
    No exceptions will be raised.
    """
    # This will definitely raise an exception
    return 1 / 0  # ZeroDivisionError!

def secure_storage(password):
    """
    Store password securely using encryption.
    Passwords are hashed and salted before storage.
    """
    # Storing in plain text - NOT SECURE
    users = {}
    users["current"] = password  # Plain text storage
    return users

def fast_algorithm(data):
    """
    This is an optimized algorithm with O(1) time complexity.
    It processes data very efficiently.
    """
    # O(n^2) algorithm - NOT efficient
    result = 0
    for i in range(len(data)):
        for j in range(len(data)):
            result += data[i] * data[j]
    return result

# ==========================================
# INCONSISTENT COMMENTING STYLES
# ==========================================

def mixed_comment_styles():
    """
    This function demonstrates mixed commenting styles.

    Some comments use proper grammar and punctuation.
    Others are more casual or abbreviated.
    This inconsistency should be flagged.
    """
    # This is a proper comment with capitalization and punctuation.
    x = 1

    # this is a casual comment without capitalization
    y = 2

    # abbreviated comment
    z = x + y

    # This comment has proper grammar and explains the next operation.
    result = z * 2

    return result

# ==========================================
# CODE IN COMMENTS (SHOULD BE FLAGGED)
# ==========================================

def example_function():
    """
    This function does something useful.

    Example usage:
    # result = example_function()  # This is code in a comment
    # print(result)  # More code in comments

    Don't do this in real docstrings.
    """
    # TODO: Implement this function
    # For now, just return None
    # return None  # Commented out code
    pass

def bad_practice_function():
    """
    This function shows bad practices.

    # Incorrect way:
    # def bad_way():
    #     return "bad"

    # Correct way:
    Use proper docstring formatting instead of commented code.
    """
    # This function is not implemented
    # It serves as an example of what not to do
    # TODO: Remove this function
    return "example"

# ==========================================
# GRAMMATICAL ERRORS IN COMMENTS (SHOULD BE FLAGGED)
# ==========================================

def fuction_with_typos():
    """
    This fuction have many gramatical errors.
    It dont follow proper english rules.
    The docstring is ful of mistakes and shud be fixed.
    """
    # this comment have bad grammar to
    # it dont use proper capitalization
    # and the punctuation is missing
    x = 1 + 1  # add two numbers together
    return x

def inconsistent_formatting():
    """
    this docstring dont use proper capitalization.

    Some lines have proper punctuation. Others don't
    The formatting is inconsistent and hard to read.

    Args:
        no parameters here.

    Returns:
        some result value.
    """
    # Some comments have periods. Others don't
    a = 1
    # this comment is fine
    b = 2  # this one too
    # but this one doesn't have punctuation
    c = a + b

    return c  # return the result

# ==========================================
# OVER-COMMENTED SIMPLE CODE (SHOULD BE FLAGGED)
# ==========================================

def overly_commented_simple_code():
    """
    This function adds 1 to a number.
    It performs a simple increment operation.
    The function takes an integer and returns the incremented value.
    This is a very straightforward mathematical operation.
    """
    # Get the input parameter
    # The parameter is called 'number'
    # It should be an integer
    number = number  # This line is redundant but has a comment

    # Prepare to add 1 to the number
    # We will use the addition operator
    # Addition is a basic arithmetic operation
    # The number 1 is the increment value
    increment_value = 1

    # Perform the addition
    # Add the increment value to the number
    # This will give us the result
    # The result is the incremented number
    result = number + increment_value

    # Return the result
    # The result is the final answer
    # This completes the function
    # The function has finished executing
    return result

# ==========================================
# COPY-PASTE ERRORS IN DOCSTRINGS
# ==========================================

def copy_paste_error_function():
    """
    This function processes user authentication.

    It validates user credentials and returns authentication status.
    The function checks if the username and password are correct.
    It returns True if authentication is successful, False otherwise.

    Args:
        username (str): The username to authenticate
        password (str): The password to authenticate

    Returns:
        bool: Authentication result

    Note: This function processes user authentication.
    It validates user credentials and returns authentication status.
    The function checks if the username and password are correct.
    It returns True if authentication is successful, False otherwise.
    """
    # This is copied from another function
    # It doesn't match what this function actually does
    return "This function doesn't authenticate anything!"

def repeated_content():
    """
    This function handles data processing.

    It processes input data and returns processed results.
    The function takes data as input and processes it accordingly.
    It returns the processed data as output.

    Processing involves validation, transformation, and formatting.
    The function ensures data integrity throughout the process.
    It handles various data types and edge cases appropriately.

    Args:
        data: Input data to process

    Returns:
        Processed data

    The function handles data processing.
    It processes input data and returns processed results.
    The function takes data as input and processes it accordingly.
    It returns the processed data as output.
    """
    # Repeated logic from somewhere else
    # This comment is copied
    return data.upper() if data else ""

# ==========================================
# TECHNICAL DEBT COMMENTS (SHOULD BE FLAGGED)
# ==========================================

def technical_debt_function():
    """
    This function has some technical debt.
    TODO: Refactor this function completely.
    FIXME: This code is messy and needs cleanup.
    HACK: Using this workaround because the proper way is too slow.
    XXX: This is temporary code that should be removed.
    """
    # TODO: Fix this implementation
    # FIXME: This is broken
    # HACK: Temporary workaround
    # XXX: Remove this ASAP

    # This code is a mess but works for now
    result = "temporary result"
    return result

def deprecated_function():
    """
    This function is deprecated.
    @deprecated: Use new_function instead.
    This function will be removed in version 2.0.
    """
    # DEPRECATED: Do not use
    # This function is old and broken
    import warnings
    warnings.warn("This function is deprecated", DeprecationWarning)

    return "old result"

# ==========================================
# AUTO-GENERATED COMMENT PATTERNS
# ==========================================

def auto_generated_function():
    """
    This is an auto-generated function.

    Generated by: Code Generator v1.0
    Template: basic_function_template
    Parameters:
    - name: auto_generated_function
    - args: []
    - return_type: str

    This function was automatically generated and may contain errors.
    Please review and test thoroughly before use.
    """
    # Auto-generated code block
    # Do not modify manually
    # Generated on: 2024-01-01
    # Generator version: 1.0.0

    return "auto-generated result"

def template_generated():
    """
    Function generated from template.

    Template variables:
    - function_name: template_generated
    - description: Function generated from template
    - author: Template Generator
    - version: 1.0

    This function follows the standard template pattern.
    All template-generated functions have similar structure.
    """
    # Template-generated content
    # Standard implementation
    # Follows template guidelines

    return "template result"

# ==========================================
# CULTURE-SPECIFIC LANGUAGE ISSUES
# ==========================================

def non_native_english():
    """
    This function make calculation for the total sum.

    It take list of numbers and calculate the summation.
    The function return the total value after addition.
    Is very useful for mathematical operations.
    """
    # calculate sum of numbers
    # use loop for addition
    # return final result
    total = 0
    for num in numbers:
        total = total + num  # add number to total
    return total

def awkward_translations():
    """
    This function "does the thing" with the data.

    It "handles the data" in a "special way".
    The function "gives back" the "processed stuff".
    Is "good" for "data work".
    """
    # do the processing
    # handle the data
    # make it good
    processed = []
    for item in data:
        processed.append(item * 2)  # double the item
    return processed  # give back result

# ==========================================
# COMMENT ROT (OUTDATED COMMENTS)
# ==========================================

def evolved_function():
    """
    This function sorts a list in ascending order using bubble sort.
    It has O(n^2) time complexity and is very efficient for large datasets.
    The algorithm repeatedly steps through the list, compares adjacent elements,
    and swaps them if they are in the wrong order.
    """
    # This was originally bubble sort
    # But we changed it to use Python's built-in sort
    # The comment above is now wrong
    # But we're keeping it for this test
    numbers.sort()  # Actually using Timsort, not bubble sort
    return numbers

def refactored_code():
    """
    This function connects to the MySQL database on localhost.
    It uses the root user with no password for authentication.
    The database name is 'test' and it connects on port 3306.
    """
    # Code was refactored to use PostgreSQL
    # But comments weren't updated
    # Still talks about MySQL
    import psycopg2
    conn = psycopg2.connect(
        host="localhost",
        user="postgres",
        password="secure_password",
        database="production_db",
        port=5432
    )
    return conn

# ==========================================
# SECRETS IN COMMENTS (SHOULD BE FLAGGED BY SECRETS CHECKER TOO)
# ==========================================

def function_with_secrets_in_comments():
    """
    This function connects to the production database.

    Database credentials:
    - Host: prod-db.example.com
    - User: admin
    - Password: super_secret_prod_password_123!
    - API Key: sk-prod-1234567890abcdef1234567890abcdef12345678
    """
    # API key for production: sk-1234567890abcdef1234567890abcdef12345678
    # Database password: db_password_prod_456!
    # JWT secret: my_jwt_secret_key_for_production_environment

    # This function doesn't actually connect to anything
    # The comments above contain sensitive information
    return "connected"

# ==========================================
# INAPPROPRIATE COMMENT CONTENT
# ==========================================

def function_with_inappropriate_comments():
    """
    This function does some boring data processing.
    Nothing interesting here, just mundane code.
    """
    # This code is ugly and I hate it
    # But it works so whatever
    # TODO: Delete this crap later
    # This function sucks

    data = [1, 2, 3, 4, 5]
    # Stupid loop
    for item in data:
        # Dumb operation
        result = item * 2

    # Whatever, just return it
    return result

# ==========================================
# MISSING OR INCOMPLETE DOCSTRINGS
# ==========================================

def incomplete_docstring(param1, param2, param3):
    """
    This function does something with three parameters.

    Args:
        param1: First parameter
        # Missing documentation for param2 and param3

    Returns:
        Some result
    """
    # Function implementation
    return param1 + param2 + param3

def missing_examples():
    """
    This function performs complex calculations.

    It takes multiple parameters and returns a computed result.
    The calculation involves several mathematical operations.

    Args:
        x: First number
        y: Second number
        operation: Type of operation to perform

    Returns:
        Result of the calculation
    """
    # Implementation would go here
    # But docstring doesn't show how to use it
    if operation == "add":
        return x + y
    elif operation == "multiply":
        return x * y
    else:
        return 0

# ==========================================
# OVER-ENGINEERED DOCSTRINGS FOR SIMPLE FUNCTIONS
# ==========================================

def simple_increment(x):
    """
    This function performs the increment operation on an integer value.

    The increment operation involves adding the value of one to the input
    parameter. This is a fundamental arithmetic operation that increases
    the magnitude of the input by a single unit. The function ensures type
    safety by expecting an integer input and returning an integer result.

    The mathematical definition of increment can be expressed as:
    f(x) = x + 1, where x is an integer and f(x) is the incremented value.

    This operation is atomic and thread-safe in most computing environments.
    It does not modify the input value but returns a new value instead.

    Args:
        x (int): The integer value to be incremented

    Returns:
        int: The incremented integer value

    Raises:
        TypeError: If the input is not an integer

    Examples:
        >>> simple_increment(5)
        6
        >>> simple_increment(-1)
        0

    Note:
        This function only works with integer values. For floating-point
        increment operations, consider using different approaches.
    """
    return x + 1

