"""Sample code for testing various patterns."""

# This is a sample Python file with various patterns for testing

def calculate_average(numbers):
    """Calculate the average of a list of numbers."""
    if not numbers:
        return 0

    total = 0
    for num in numbers:
        total += num

    return total / len(numbers)


class DataProcessor:
    """A class that processes data."""

    def __init__(self):
        self.data = []

    def add_item(self, item):
        """Add an item to the data list."""
        self.data.append(item)

    def process_all(self):
        """Process all items in the data list."""
        results = []
        for item in self.data:
            # Process each item
            processed = item * 2
            results.append(processed)

        return results


# Some potentially problematic code
def get_user_data(user_id):
    """Get user data by ID."""
    # Missing validation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Missing error handling
    return execute_query(query)


def complex_function(param1, param2, param3, param4, param5):
    """A complex function with many parameters."""
    result = param1 + param2 + param3 + param4 + param5

    # Overly complex logic
    if result > 100:
        if result > 200:
            if result > 300:
                return result * 2
            else:
                return result * 1.5
        else:
            return result
    else:
        return result / 2


# AI-like generic code
def helper_function(data):
    """This is a helper function that processes data."""
    # The function takes some data as input
    # It processes the data in some way
    # Then it returns the processed data

    processed_data = []
    for item in data:
        # Process each item
        processed_item = item  # Placeholder processing
        processed_data.append(processed_item)

    # Return the processed data
    return processed_data
