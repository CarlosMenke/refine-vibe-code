"""
Comprehensive stress test file for edge cases checker.
Tests various potential bugs, missing error handling, and complex scenarios.
"""

import os
import json
import requests
from typing import List, Dict, Any, Optional
import tempfile

# ==========================================
# NULL/UNDEFINED/NONE HANDLING ISSUES
# ==========================================

def process_user_data(user_data):
    """Missing null checks."""
    # No check if user_data is None
    name = user_data['name']  # KeyError if 'name' doesn't exist
    email = user_data.get('email')  # This is safe, but name access isn't

    return f"{name} <{email}>"

def divide_numbers(a, b):
    """Division by zero not handled."""
    return a / b  # ZeroDivisionError if b is 0

def access_list_element(data_list, index):
    """No bounds checking."""
    return data_list[index]  # IndexError if index out of bounds

def get_nested_value(data):
    """Deep nesting without safety checks."""
    return data['user']['profile']['settings']['theme']  # Multiple KeyError possibilities

# ==========================================
# TYPE CONVERSION ISSUES
# ==========================================

def convert_to_int(value):
    """Unsafe type conversion."""
    return int(value)  # ValueError if not convertible

def string_concatenation(mixed_data):
    """Unsafe string operations."""
    result = ""
    for item in mixed_data:
        result += str(item)  # May not behave as expected for complex objects
    return result

def numeric_operations(a, b):
    """Missing type validation for math."""
    return a + b  # TypeError if incompatible types

# ==========================================
# RESOURCE MANAGEMENT ISSUES
# ==========================================

def read_file_unsafe(filename):
    """File operations without proper error handling."""
    with open(filename, 'r') as f:  # FileNotFoundError not handled
        return f.read()

def network_request(url):
    """Network calls without timeout or error handling."""
    response = requests.get(url)  # No timeout, may hang forever
    return response.json()  # May fail if not JSON

def database_connection():
    """Database operations without cleanup."""
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    # No try/finally, connection may leak
    cursor.execute("SELECT 1")
    return cursor.fetchone()

# ==========================================
# CONCURRENCY AND RACE CONDITIONS
# ==========================================

import threading

shared_counter = 0

def increment_counter():
    """Race condition in shared state."""
    global shared_counter
    # No synchronization
    current = shared_counter
    # Thread could be interrupted here
    shared_counter = current + 1

def append_to_shared_list(item, shared_list):
    """Unsafe concurrent list operations."""
    # No synchronization
    shared_list.append(item)

# ==========================================
# INPUT VALIDATION ISSUES
# ==========================================

def process_user_input(user_input):
    """No input validation or sanitization."""
    # Could be any type, any size, any content
    result = user_input.upper()
    return result

def parse_json_input(json_string):
    """Unsafe JSON parsing."""
    return json.loads(json_string)  # JSONDecodeError not handled

def evaluate_expression(expression):
    """Dangerous expression evaluation."""
    return eval(expression)  # Extremely dangerous, allows code execution

# ==========================================
# BOUNDARY CONDITION ISSUES
# ==========================================

def process_list_items(items):
    """Off-by-one errors and boundary issues."""
    result = []
    for i in range(len(items) + 1):  # Off-by-one: will cause IndexError
        result.append(items[i] * 2)
    return result

def fibonacci_recursive(n):
    """Stack overflow for large inputs."""
    if n <= 1:
        return n
    return fibonacci_recursive(n-1) + fibonacci_recursive(n-2)  # Stack overflow for n > 1000

def allocate_memory(size):
    """Memory exhaustion."""
    return [0] * size  # Could exhaust memory for large size

# ==========================================
# LOGIC ERRORS AND EDGE CASES
# ==========================================

def validate_age(age):
    """Logic error in validation."""
    if age > 0 and age < 150:  # What about age = 0? Negative ages?
        return True
    return False

def calculate_discount(price, discount_percent):
    """Calculation errors."""
    if discount_percent > 100:  # Should validate 0 <= discount_percent <= 100
        discount_percent = 100
    return price * (1 - discount_percent / 100)  # Wrong: should be discount_percent / 100.0

def check_password_strength(password):
    """Incomplete validation logic."""
    if len(password) < 8:
        return False
    # Missing checks for uppercase, lowercase, numbers, special chars
    return True

# ==========================================
# ERROR HANDLING ISSUES
# ==========================================

def risky_operation():
    """Bare except clause."""
    try:
        result = 1 / 0  # Will raise ZeroDivisionError
    except:  # Catches ALL exceptions, including KeyboardInterrupt
        return "error"
    return result

def silent_failure():
    """Ignores exceptions completely."""
    data = {"key": "value"}
    try:
        return data['missing_key']  # KeyError
    except KeyError:
        pass  # Silently ignores error, returns None implicitly

def inappropriate_exception_handling():
    """Catches wrong exception type."""
    try:
        int("not_a_number")  # ValueError
    except TypeError:  # Wrong exception type
        return "error"

# ==========================================
# ASYNC AND AWAIT ISSUES
# ==========================================

import asyncio

async def async_operation_with_timeout():
    """Async operation without proper timeout handling."""
    await asyncio.sleep(10)  # Could be cancelled but no timeout handling
    return "done"

async def async_resource_leak():
    """Async context manager not used properly."""
    # File not properly closed in async context
    file = open("data.txt", "w")
    await asyncio.sleep(1)
    file.write("data")
    # File may not be closed if coroutine is cancelled
    file.close()

# ==========================================
# MEMORY AND PERFORMANCE ISSUES
# ==========================================

def inefficient_algorithm(data):
    """O(n^2) algorithm that could be O(n)."""
    result = []
    for i in range(len(data)):
        for j in range(i):  # Redundant computation
            if data[i] == data[j]:
                result.append(data[i])
                break
    return result

def memory_leak_simulation():
    """Accumulates data without cleanup."""
    cache = {}
    def add_to_cache(key, value):
        cache[key] = value  # Grows indefinitely
        return cache
    return add_to_cache

# ==========================================
# CONFIGURATION AND ENVIRONMENT ISSUES
# ==========================================

def load_config():
    """Configuration loading without validation."""
    config_file = os.getenv("CONFIG_FILE", "default.json")

    with open(config_file, 'r') as f:  # File may not exist
        config = json.load(f)  # May not be valid JSON

    # No validation of required fields
    database_url = config['database']['url']  # KeyError if missing
    return database_url

def environment_variable_usage():
    """Unsafe environment variable usage."""
    port = int(os.getenv("PORT", "8000"))  # ValueError if not integer
    debug = os.getenv("DEBUG", "false").lower() == "true"  # String comparison issues

    return port, debug

# ==========================================
# API AND INTERFACE ISSUES
# ==========================================

def api_call_with_retry(url, max_retries=3):
    """Retry logic with potential infinite loops."""
    retries = 0
    while retries < max_retries:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            else:
                retries += 1
                continue  # No delay between retries, may overwhelm server
        except requests.RequestException:
            retries += 1
            continue

    return None

def callback_function_registration(callback):
    """Callback registration without validation."""
    # No validation that callback is callable
    # No check for callback signature
    callbacks = []
    callbacks.append(callback)
    return callbacks

# ==========================================
# DATA STRUCTURE ISSUES
# ==========================================

def process_nested_dict(data):
    """Complex nested data structure handling."""
    if 'users' in data:
        for user in data['users']:
            if 'posts' in user:
                for post in user['posts']:
                    if 'comments' in post:
                        for comment in post['comments']:
                            # Deep nesting, easy to miss None checks
                            return comment['text']  # KeyError if 'text' missing
    return None

def circular_reference_risk():
    """Risk of circular references."""
    class Node:
        def __init__(self, value):
            self.value = value
            self.children = []
            self.parent = None  # Could create circular references

        def add_child(self, child):
            self.children.append(child)
            child.parent = self  # Creates circular reference

    return Node

# ==========================================
# TIME AND SCHEDULING ISSUES
# ==========================================

import time

def polling_loop():
    """Polling without proper timing controls."""
    while True:
        # Check for updates
        if check_for_updates():
            break
        time.sleep(0.1)  # May still be too frequent, no backoff

def timeout_without_proper_handling():
    """Timeout implementation issues."""
    start_time = time.time()
    while time.time() - start_time < 10:  # 10 second timeout
        try:
            result = perform_operation()
            return result
        except Exception:
            continue  # Ignores errors, may loop forever

    return None

# ==========================================
# ENCODING AND CHARACTER ISSUES
# ==========================================

def process_text_file(filename):
    """Encoding issues not handled."""
    with open(filename, 'r') as f:  # No encoding specified
        content = f.read()

    # May fail with UnicodeDecodeError for non-ASCII files
    return content.upper()

def url_encoding_issues(url):
    """URL handling without proper encoding."""
    # No URL validation or encoding
    response = requests.get(url)
    return response.text

# ==========================================
# MATHEMATICAL AND NUMERIC ISSUES
# ==========================================

def calculate_average(numbers):
    """Division by zero not handled."""
    total = sum(numbers)
    return total / len(numbers)  # ZeroDivisionError if numbers is empty

def floating_point_precision():
    """Floating point precision issues."""
    result = 0.1 + 0.2  # May not equal 0.3 due to floating point precision
    return result == 0.3  # Will be False

def integer_overflow_simulation():
    """Large number handling."""
    result = 2 ** 1000  # Creates very large integer, could cause issues in some contexts
    return result

# ==========================================
# SECURITY-RELATED EDGE CASES
# ==========================================

def command_execution(command):
    """Command injection vulnerability."""
    import subprocess
    # No validation or sanitization
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout.decode()

def path_traversal(filename):
    """Path traversal vulnerability."""
    # No path validation
    with open(filename, 'r') as f:  # Could access files outside intended directory
        return f.read()

def sql_injection_simulation(query_param):
    """SQL injection (simplified example)."""
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Direct string interpolation - vulnerable
    query = f"SELECT * FROM users WHERE name = '{query_param}'"
    cursor.execute(query)  # SQL injection possible

    return cursor.fetchall()

# ==========================================
# COMPLEX BUSINESS LOGIC ISSUES
# ==========================================

def complex_business_logic(order):
    """Complex business logic with missing validations."""
    total = 0

    # Multiple nested conditions without proper validation
    if 'items' in order:
        for item in order['items']:
            if 'price' in item and 'quantity' in item:
                # No validation of price/quantity types or ranges
                subtotal = item['price'] * item['quantity']
                total += subtotal

    # Tax calculation without proper validation
    tax_rate = order.get('tax_rate', 0.1)  # Default tax rate
    tax = total * tax_rate

    # Discount calculation
    if 'discount_code' in order:
        # No validation of discount code
        discount = total * 0.1  # Fixed 10% discount
        total -= discount

    return total + tax

# ==========================================
# STATE MANAGEMENT ISSUES
# ==========================================

class StateManager:
    """State management with race conditions."""

    def __init__(self):
        self.state = {}
        self.lock = threading.Lock()  # Lock exists but not always used

    def update_state(self, key, value):
        # Sometimes uses lock, sometimes doesn't
        if key.startswith('critical'):
            with self.lock:
                self.state[key] = value
        else:
            self.state[key] = value  # Race condition

    def get_state(self, key):
        return self.state.get(key)  # No synchronization

# ==========================================
# EXTERNAL DEPENDENCY ISSUES
# ==========================================

def external_api_call(api_key, data):
    """External API calls without proper error handling."""
    headers = {'Authorization': f'Bearer {api_key}'}
    response = requests.post(
        'https://api.example.com/process',
        json=data,
        headers=headers,
        timeout=5  # Timeout set but may not be sufficient
    )

    # No status code validation
    return response.json()

def third_party_library_usage():
    """Third-party library usage without error handling."""
    try:
        import some_unreliable_library
        result = some_unreliable_library.process_data(data)
        return result
    except ImportError:
        # Library not installed
        return None
    except Exception as e:
        # Generic exception handling
        print(f"Error: {e}")
        return None

# ==========================================
# CONFIGURATION VALIDATION ISSUES
# ==========================================

def load_and_validate_config(config_path):
    """Configuration loading with incomplete validation."""
    with open(config_path, 'r') as f:
        config = json.load(f)

    # Checks some fields but not others
    required_fields = ['database_url', 'api_key']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field: {field}")

    # No validation of field types or values
    # No validation of optional fields
    # No schema validation

    return config

# ==========================================
# PERFORMANCE MONITORING ISSUES
# ==========================================

def performance_critical_function(data):
    """Performance-critical function without monitoring."""
    start_time = time.time()

    # Complex computation without progress tracking
    result = []
    for item in data:
        # CPU-intensive operation
        processed = item ** 2  # Could be very slow for large data
        result.append(processed)

    end_time = time.time()

    # No logging of performance metrics
    # No early termination for slow operations
    # No circuit breaker pattern

    return result

# ==========================================
# TESTING AND MOCKING ISSUES
# ==========================================

def function_with_side_effects(filename):
    """Function with side effects that are hard to test."""
    # Writes to file system
    with open(filename, 'w') as f:
        f.write("data")

    # Makes network call
    requests.get("https://example.com/notify")

    # Uses current time
    current_time = time.time()

    return current_time

# ==========================================
# SERIALIZATION AND DESERIALIZATION ISSUES
# ==========================================

def serialize_object(obj):
    """Serialization without safety checks."""
    return json.dumps(obj)  # May fail for complex objects

def deserialize_data(data_string):
    """Deserialization without validation."""
    return json.loads(data_string)  # May create unexpected objects

# ==========================================
# CACHE MANAGEMENT ISSUES
# ==========================================

class CacheManager:
    """Cache with potential issues."""

    def __init__(self):
        self.cache = {}
        self.max_size = 1000  # No enforcement

    def get(self, key):
        return self.cache.get(key)  # No cache expiration

    def put(self, key, value):
        self.cache[key] = value  # Grows indefinitely
        # No size limit enforcement
        # No eviction policy

# ==========================================
# LOGGING AND MONITORING ISSUES
# ==========================================

import logging

def function_with_logging(data):
    """Logging without proper configuration."""
    logging.info(f"Processing data: {data}")  # May not be configured

    try:
        result = risky_operation(data)
        logging.info(f"Success: {result}")
        return result
    except Exception as e:
        logging.error(f"Error: {e}")  # Generic error logging
        # No structured logging
        # No error classification
        raise

# ==========================================
# INITIALIZATION AND CLEANUP ISSUES
# ==========================================

class ResourceManager:
    """Resource manager with cleanup issues."""

    def __init__(self):
        self.resources = []
        self.initialized = False

    def initialize(self):
        # Initialization that might fail
        self.resources.append(open("file1.txt", "w"))
        self.resources.append(open("file2.txt", "w"))
        self.initialized = True

    def cleanup(self):
        # Manual cleanup - easy to forget to call
        for resource in self.resources:
            resource.close()
        self.resources.clear()

    def process(self):
        if not self.initialized:
            self.initialize()  # Initialization during processing

        # Use resources
        for resource in self.resources:
            resource.write("data")

        # Cleanup might be forgotten
        # self.cleanup()

# ==========================================
# THREADING AND SYNCHRONIZATION ISSUES
# ==========================================

class ThreadedProcessor:
    """Threaded processing with synchronization issues."""

    def __init__(self):
        self.results = []
        self.threads = []

    def process_item(self, item):
        # Process item (no synchronization)
        result = item * 2
        self.results.append(result)  # Race condition

    def process_batch(self, items):
        for item in items:
            thread = threading.Thread(target=self.process_item, args=(item,))
            self.threads.append(thread)
            thread.start()

        # Wait for threads
        for thread in self.threads:
            thread.join()

        return self.results

# ==========================================
# COMPLEX CONDITIONAL LOGIC ISSUES
# ==========================================

def complex_conditional_logic(user, order, payment):
    """Complex conditional logic with missing cases."""

    # Multiple nested conditions
    if user and user.get('active'):
        if order and order.get('total', 0) > 0:
            if payment and payment.get('method'):
                if payment['method'] == 'credit_card':
                    if 'card_number' in payment:
                        # Process credit card payment
                        return process_credit_card(order['total'], payment['card_number'])
                    else:
                        return "Missing card number"
                elif payment['method'] == 'paypal':
                    # Process PayPal payment
                    return process_paypal(order['total'])
                else:
                    return "Unsupported payment method"
            else:
                return "Missing payment method"
        else:
            return "Invalid order total"
    else:
        return "Inactive user"

    # What if user is None? What if order is None? What if payment is None?
    # What if payment method is invalid? What if card number is invalid?

# ==========================================
# FUNCTION COMPOSITION ISSUES
# ==========================================

def compose_functions(func1, func2, data):
    """Function composition without validation."""
    # No validation that func1 and func2 are callable
    # No validation of function signatures
    result1 = func1(data)
    result2 = func2(result1)
    return result2

def pipeline_processing(data, processors):
    """Pipeline processing with error handling issues."""
    result = data
    for processor in processors:
        try:
            result = processor(result)  # May fail
        except Exception:
            # Ignores processor failures
            continue
    return result

# ==========================================
# METADATA AND REFLECTION ISSUES
# ==========================================

def dynamic_method_call(obj, method_name, *args):
    """Dynamic method calling without safety."""
    method = getattr(obj, method_name)  # May not exist
    return method(*args)  # May have wrong signature

def inspect_object_attributes(obj):
    """Object attribute inspection without validation."""
    attributes = {}
    for attr_name in dir(obj):
        if not attr_name.startswith('_'):  # Filter private attributes
            attr_value = getattr(obj, attr_name)
            attributes[attr_name] = attr_value  # May access sensitive data
    return attributes

# ==========================================
# COMPLEX DATA TRANSFORMATIONS
# ==========================================

def transform_complex_data(data):
    """Complex data transformation with potential issues."""
    result = {}

    # Multiple transformations without validation
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                # Transform list to dict
                result[key] = {f"item_{i}": item for i, item in enumerate(value)}
            elif isinstance(value, str):
                # Transform string
                result[key] = value.upper()
            else:
                # Keep as-is
                result[key] = value
    else:
        result = data  # No transformation for non-dict

    # Missing validation of transformation results
    # No error handling for transformation failures
    return result

# ==========================================
# ASYNC GENERATOR AND ITERATOR ISSUES
# ==========================================

async def async_generator_with_issues():
    """Async generator with potential issues."""
    for i in range(1000000):  # Large range
        yield i * 2  # May consume large amounts of memory

def iterator_with_side_effects():
    """Iterator with side effects."""
    class SideEffectIterator:
        def __init__(self, data):
            self.data = data
            self.index = 0

        def __iter__(self):
            return self

        def __next__(self):
            if self.index >= len(self.data):
                raise StopIteration

            # Side effect: modifies data during iteration
            item = self.data[self.index]
            self.data[self.index] = item * 2  # Modifies original data
            self.index += 1

            return item

    return SideEffectIterator

# ==========================================
# CONTEXT MANAGER ISSUES
# ==========================================

class ProblematicContextManager:
    """Context manager with issues."""

    def __init__(self, resource):
        self.resource = resource
        self.allocated = False

    def __enter__(self):
        # Allocate resource
        self.resource.allocate()
        self.allocated = True
        return self.resource

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Cleanup
        if self.allocated:
            self.resource.cleanup()
        # Doesn't handle exceptions properly
        # Doesn't return True to suppress exceptions

def use_context_manager():
    """Using context manager incorrectly."""
    manager = ProblematicContextManager(SomeResource())

    # Manual context management (error-prone)
    resource = manager.__enter__()
    try:
        # Use resource
        result = resource.process()
        return result
    finally:
        manager.__exit__(None, None, None)  # Manual cleanup

# ==========================================
# DECORATOR ISSUES
# ==========================================

def problematic_decorator(func):
    """Decorator with issues."""
    def wrapper(*args, **kwargs):
        # Pre-processing
        print("Starting function")

        try:
            result = func(*args, **kwargs)
            print("Function completed")
            return result
        except Exception as e:
            print(f"Function failed: {e}")
            raise  # Re-raises but doesn't preserve stack trace properly

    return wrapper

@problematic_decorator
def decorated_function(x, y):
    """Function with decorator issues."""
    return x / y  # May raise ZeroDivisionError

# ==========================================
# CLASS DESIGN ISSUES
# ==========================================

class ProblematicClass:
    """Class with design issues."""

    def __init__(self, value):
        self.value = value
        self._cache = {}  # Cache that grows indefinitely

    def process(self, data):
        # Uses cache without size limits
        cache_key = hash(str(data))
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Expensive computation
        result = data * self.value

        # Cache result (unbounded growth)
        self._cache[cache_key] = result

        return result

    def __del__(self):
        # Destructor may not be called reliably
        print("Cleaning up")
        self._cache.clear()

# ==========================================
# MODULE-LEVEL ISSUES
# ==========================================

# Global state that can cause issues
global_state = {}

def modify_global_state(key, value):
    """Modifies global state without synchronization."""
    global_state[key] = value

def read_global_state(key):
    """Reads global state without validation."""
    return global_state.get(key)  # May return None unexpectedly

# Module-level initialization that might fail
try:
    import some_optional_dependency
    OPTIONAL_FEATURE_AVAILABLE = True
except ImportError:
    OPTIONAL_FEATURE_AVAILABLE = False

def use_optional_feature():
    """Uses optional feature without checking availability."""
    if OPTIONAL_FEATURE_AVAILABLE:
        return some_optional_dependency.do_something()
    else:
        # Fallback that might not work properly
        return "fallback_result"
