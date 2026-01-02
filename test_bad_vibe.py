"""Test file with AI-generated bad coding patterns."""

def bad_function():
    """Function with multiple AI-generated bad patterns."""

    # Bad loop pattern - range(len())
    data = [1, 2, 3, 4, 5]
    result = []
    for i in range(len(data)):
        result.append(data[i] * 2)

    # Unsafe practice - bare except
    try:
        value = int("not_a_number")
        print(value)
    except:  # This is dangerous!
        pass

    # Inefficient string concatenation
    message = ""
    for item in ["hello", "world", "test"]:
        message += item + " "

    return result, message

def mutable_default_bad():
    """Classic mutable default argument mistake."""
    def add_to_list(item, my_list=[]):  # BAD!
        my_list.append(item)
        return my_list

    # This will accumulate across calls
    list1 = add_to_list("a")
    list2 = add_to_list("b")  # Will contain ["a", "b"]
    return list1, list2

def redundant_loop():
    """Two loops doing the same thing."""
    numbers = [1, 2, 3, 4, 5]

    # First loop
    evens = []
    for num in numbers:
        if num % 2 == 0:
            evens.append(num)

    # Redundant second loop
    even_squares = []
    for even in evens:
        even_squares.append(even ** 2)

    return even_squares

