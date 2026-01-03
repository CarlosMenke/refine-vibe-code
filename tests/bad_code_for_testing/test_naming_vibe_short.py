"""
Comprehensive stress test file for naming vibe checker.
Tests various AI-generated naming patterns and poor naming conventions.
"""

# ==========================================
# AI-GENERATED ROBOTIC NAMING PATTERNS
# ==========================================

def process_user_data_function(user_data_list):
    """Function with generic, robotic naming."""
    processed_user_data_list = []
    for user_data_item in user_data_list:
        processed_user_data_item = user_data_item * 2
        processed_user_data_list.append(processed_user_data_item)
    return processed_user_data_list

def calculate_total_sum_value(input_number_list):
    """Function with overly verbose naming."""
    total_sum_value = 0
    for number_item in input_number_list:
        total_sum_value += number_item
    return total_sum_value

def validate_input_data_function(input_data_parameter):
    """Function with redundant naming patterns."""
    if input_data_parameter is None:
        return False
    if not isinstance(input_data_parameter, str):
        return False
    return len(input_data_parameter.strip()) > 0

# ==========================================
# INCONSISTENT NAMING CONVENTIONS
# ==========================================

def getUserData():
    """CamelCase function name (JavaScript style in Python)."""
    userData = []  # Mixed camelCase and snake_case
    for item in userData:
        processedItem = item * 2
        userData.append(processedItem)
    return userData

def calculateTotal(user_list):
    """Mixed conventions."""
    totalValue = 0  # camelCase
    for user_item in user_list:  # snake_case
        totalValue += user_item
    return totalValue

def processData(data):
    """Single word names."""
    result = []
    for item in data:
        processed = item * 2
        result.append(processed)
    return result
