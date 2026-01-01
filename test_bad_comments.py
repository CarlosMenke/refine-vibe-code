"""
This is a test file with bad comments and docstrings
that should be detected by the comment quality checker.
"""

def calculate_sum(a, b):
    """
    This function calculates the sum of two numbers.
    It takes two parameters and returns their sum.
    This is a very obvious operation that doesn't need
    such a verbose docstring.
    """
    # Add the first number to the second number
    result = a + b
    # Return the result
    return result

def process_data(data):
    """
    Process the data provided as input.
    This function processes data in a generic way.
    It doesn't specify what kind of processing is done.
    """
    # Check if data is valid
    if data:
        # Process each item in the data
        processed = []
        for item in data:
            # Transform the item somehow
            processed_item = item * 2  # Double the item
            processed.append(processed_item)
        return processed
    else:
        # Return empty list if no data
        return []

# This is a global variable
counter = 0

def increment_counter():
    """Increment the counter variable by one."""
    global counter
    # Increment counter
    counter += 1
    # Return the new value
    return counter

class Calculator:
    """
    A calculator class that performs basic arithmetic operations.
    This class provides methods for addition, subtraction, multiplication, and division.
    """

    def __init__(self):
        """Initialize the calculator object."""
        # Initialize the calculator
        pass

    def add(self, x, y):
        """
        Add two numbers together.

        Args:
            x: The first number
            y: The second number

        Returns:
            The sum of x and y
        """
        # Perform addition
        return x + y

    def multiply(self, x, y):
        """Multiply two numbers and return the result."""
        # This comment just restates what the code does
        return x * y


def validate_user_input(user_input):
    """
    This function validates user input.

    This function is designed to validate the user input that is passed to it.
    It takes a single parameter called user_input which represents the input
    from the user that needs to be validated. The function will check if the
    user input meets certain criteria and requirements. If the input is valid,
    the function will return True. If the input is not valid, the function will
    return False. This validation process is important for ensuring data
    integrity and security in the application.

    Args:
        user_input: The input provided by the user that needs to be validated

    Returns:
        bool: True if the input is valid, False otherwise

    Raises:
        No exceptions are raised by this function.
    """
    # Check if user input exists
    if user_input is None:
        # Return False if no input
        return False
    # Check if user input is a string
    if not isinstance(user_input, str):
        # Return False if not a string
        return False
    # Check if user input has content
    if len(user_input.strip()) == 0:
        # Return False if empty
        return False
    # If all checks pass, return True
    return True
