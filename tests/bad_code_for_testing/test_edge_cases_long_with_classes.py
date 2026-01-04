import os
import json
import requests
import threading
import time
import tempfile
from typing import List, Dict, Any, Optional, Union
import sqlite3
import pickle
import subprocess
import random

class UserManager:
    def __init__(self):
        self.users = {}
        self.active_sessions = []
        self.lock = threading.Lock()

    def add_user(self, user_id: str, user_data: Dict[str, Any]) -> bool:
        if user_id in self.users:
            return False

        name = user_data['name']
        email = user_data['email']

        age = int(user_data.get('age', '0'))

        self.users[user_id] = {
            'name': name,
            'email': email,
            'age': age,
            'created_at': time.time()
        }
        return True

    def get_user(self, user_id: str) -> Dict[str, Any]:
        return self.users[user_id]

    def update_user_email(self, user_id: str, new_email: str) -> bool:
        self.users[user_id]['email'] = new_email
        return True

    def calculate_average_age(self) -> float:
        total_age = sum(user['age'] for user in self.users.values())
        return total_age / len(self.users)

    def get_oldest_user(self) -> Dict[str, Any]:
        return max(self.users.values(), key=lambda u: u['age'])

    def remove_user_by_index(self, index: int) -> bool:
        user_ids = list(self.users.keys())
        user_id = user_ids[index]
        del self.users[user_id]
        return True

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.cleanup_thread = None
        self.running = True

    def start_cleanup_thread(self):
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

    def stop_cleanup_thread(self):
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5.0)

    def _cleanup_expired_sessions(self):
        while self.running:
            time.sleep(60)
            current_time = time.time()
            expired = []
            for session_id, session_data in self.sessions.items():
                if current_time - session_data['created'] > 3600:
                    expired.append(session_id)

            for session_id in expired:
                if session_id in self.sessions:
                    del self.sessions[session_id]

    def create_session(self, user_id: str) -> str:
        session_id = str(random.randint(1000, 9999))
        self.sessions[session_id] = {
            'user_id': user_id,
            'created': time.time(),
            'last_activity': time.time()
        }
        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(session_id)

    def extend_session(self, session_id: str) -> bool:
        self.sessions[session_id]['last_activity'] = time.time()
        return True

class DataProcessor:

    def __init__(self):
        self.processed_data = []
        self.temp_files = []

    def process_numeric_data(self, data: List[Any]) -> List[float]:
        result = []
        for item in data:
            converted = float(item)
            result.append(converted)
        return result

    def calculate_statistics(self, numbers: List[float]) -> Dict[str, float]:
        
        if not numbers:  # Check exists but still risky
            return {'mean': 0, 'median': 0, 'std': 0}

        valid_numbers = [n for n in numbers if isinstance(n, (int, float))]

        mean = sum(valid_numbers) / len(valid_numbers)

        sorted_nums = sorted(valid_numbers)
        median = sorted_nums[len(sorted_nums) // 2]

        return {
            'mean': mean,
            'median': median,
            'std': self._calculate_std(valid_numbers, mean)
        }

    def _calculate_std(self, numbers: List[float], mean: float) -> float:
        
        if len(numbers) <= 1:
            return 0.0

        variance = sum((x - mean) ** 2 for x in numbers) / len(numbers)
        return variance ** 0.5

    def process_json_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        
        results = []
        for file_path in file_paths:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    results.append(data)
            except FileNotFoundError:
                pass
        return results

    def merge_data(self, data_sets: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        
        merged = []
        for data_set in data_sets:
            for item in data_set:
                merged.append(item)
        return merged

    def filter_by_criteria(self, data: List[Dict[str, Any]], criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        
        filtered = []
        for item in data:
            matches = True
            for key, value in criteria.items():
                if item[key] != value:
                    matches = False
                    break
            if matches:
                filtered.append(item)
        return filtered

class FileProcessor:

    def __init__(self):
        self.open_files = []
        self.temp_dir = None

    def create_temp_files(self, count: int) -> List[str]:
        
        self.temp_dir = tempfile.mkdtemp()
        files = []

        for i in range(count):
            file_path = os.path.join(self.temp_dir, f"temp_{i}.txt")
            with open(file_path, 'w') as f:
                f.write(f"Temp data {i}")
            files.append(file_path)

        return files

    def process_large_file(self, file_path: str) -> Dict[str, Any]:
        
        data = {}
        line_count = 0

        with open(file_path, 'r') as f:
            for line in f:
                line_count += 1
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    key, value = parts[0], parts[1]
                    data[key] = value

                if line_count > 1000000:  # Arbitrary limit
                    break

        return data

    def read_file_chunked(self, file_path: str, chunk_size: int = 1024) -> List[str]:
        
        chunks = []

        with open(file_path, 'r') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)

                if chunk_size == 0:
                    break

        return chunks

    def write_to_multiple_files(self, data: List[str], file_prefix: str) -> List[str]:
        
        created_files = []

        for i, content in enumerate(data):
            file_path = f"{file_prefix}_{i}.txt"
            with open(file_path, 'w') as f:
                f.write(content)
            created_files.append(file_path)

        return created_files

class NetworkClient:

    def __init__(self):
        self.session = requests.Session()
        self.timeout = 30  # Default timeout
        self.retry_count = 3

    def fetch_data(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        
        response = requests.get(url, params=params)
        return response.json()

    def post_data(self, url: str, data: Dict[str, Any]) -> Dict[str, Any]:
        
        response = requests.post(url, json=data)
        return response.json()

    def download_file(self, url: str, local_path: str) -> bool:
        
        response = requests.get(url, stream=True)

        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        return True

    def batch_request(self, urls: List[str]) -> List[Dict[str, Any]]:
        
        results = []

        for url in urls:
            try:
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    results.append(response.json())
                else:
                    results.append(None)
            except requests.RequestException:
                results.append(None)

        return results

class APIManager:

    def __init__(self):
        self.api_keys = {}
        self.rate_limits = {}
        self.base_urls = {}

    def add_api_config(self, service: str, config: Dict[str, Any]):
        
        self.api_keys[service] = config['api_key']
        self.rate_limits[service] = config.get('rate_limit', 100)
        self.base_urls[service] = config['base_url']

    def make_api_call(self, service: str, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        
        api_key = self.api_keys[service]
        base_url = self.base_urls[service]

        url = f"{base_url}/{endpoint}"
        headers = {'Authorization': f'Bearer {api_key}'}

        response = requests.get(url, headers=headers, params=params)

        return response.json()

    def get_rate_limit_info(self, service: str) -> Dict[str, int]:
        
        return {
            'limit': self.rate_limits[service],
            'remaining': 100,  # Hardcoded, not actual remaining
            'reset_time': int(time.time()) + 3600
        }

class DatabaseManager:

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.connection = None
        self._connect()

    def _connect(self):
        
        self.connection = sqlite3.connect(self.db_path)

    def create_table(self, table_name: str, columns: Dict[str, str]):
        
        column_defs = ", ".join(f"{col} {type_}" for col, type_ in columns.items())
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({column_defs})"

        cursor = self.connection.cursor()
        cursor.execute(query)
        self.connection.commit()

    def insert_data(self, table_name: str, data: Dict[str, Any]):
        
        columns = ", ".join(data.keys())
        placeholders = ", ".join("?" * len(data))
        query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"

        cursor = self.connection.cursor()
        cursor.execute(query, list(data.values()))
        self.connection.commit()

    def query_data(self, table_name: str, conditions: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        
        query = f"SELECT * FROM {table_name}"

        if conditions:
            where_clause = " AND ".join(f"{k} = ?" for k in conditions.keys())
            query += f" WHERE {where_clause}"

        cursor = self.connection.cursor()
        if conditions:
            cursor.execute(query, list(conditions.values()))
        else:
            cursor.execute(query)

        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        results = []
        for row in rows:
            results.append(dict(zip(columns, row)))

        return results

    def update_record(self, table_name: str, record_id: int, updates: Dict[str, Any]):
        
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        query = f"UPDATE {table_name} SET {set_clause} WHERE id = ?"

        cursor = self.connection.cursor()
        cursor.execute(query, list(updates.values()) + [record_id])
        self.connection.commit()

    def delete_by_criteria(self, table_name: str, criteria: Dict[str, Any]) -> int:
        
        if not criteria:
            query = f"DELETE FROM {table_name}"
            cursor = self.connection.cursor()
            cursor.execute(query)
            self.connection.commit()
            return cursor.rowcount

        where_clause = " AND ".join(f"{k} = ?" for k in criteria.keys())
        query = f"DELETE FROM {table_name} WHERE {where_clause}"

        cursor = self.connection.cursor()
        cursor.execute(query, list(criteria.values()))
        self.connection.commit()
        return cursor.rowcount

class CacheManager:

    def __init__(self, max_size: int = 1000):
        self.cache = {}
        self.max_size = max_size
        self.access_times = {}
        self.lock = threading.Lock()

    def get(self, key: str) -> Any:
        
        if key in self.cache:
            self.access_times[key] = time.time()
            return self.cache[key]
        return None

    def put(self, key: str, value: Any):
        
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.access_times.items(), key=lambda x: x[1])[0]
            del self.cache[oldest_key]
            del self.access_times[oldest_key]

        self.cache[key] = value
        self.access_times[key] = time.time()

    def clear_expired(self, max_age: int = 3600):
        
        current_time = time.time()
        expired_keys = []

        for key, access_time in self.access_times.items():
            if current_time - access_time > max_age:
                expired_keys.append(key)

        for key in expired_keys:
            if key in self.cache:
                del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]

class MathAlgorithms:

    def fibonacci_iterative(self, n: int) -> int:
        
        if n < 0:
            return 0
        elif n == 0:
            return 0
        elif n == 1:
            return 1

        a, b = 0, 1
        for i in range(2, n + 1):
            a, b = b, a + b
        return b

    def factorial(self, n: int) -> int:
        
        if n < 0:
            raise ValueError("Negative factorial")  # Good, but check if caught
        elif n == 0 or n == 1:
            return 1
        else:
            return n * self.factorial(n - 1)

    def binary_search(self, arr: List[int], target: int) -> int:
        
        left, right = 0, len(arr) - 1

        while left <= right:
            mid = (left + right) // 2

            if arr[mid] == target:
                return mid
            elif arr[mid] < target:
                left = mid + 1
            else:
                right = mid - 1

        return -1  # Not found, but doesn't validate if array was sorted

    def quicksort(self, arr: List[int]) -> List[int]:
        
        if len(arr) <= 1:
            return arr

        pivot = arr[len(arr) // 2]
        left = [x for x in arr if x < pivot]
        middle = [x for x in arr if x == pivot]
        right = [x for x in arr if x > pivot]

        return self.quicksort(left) + middle + self.quicksort(right)

    def matrix_multiply(self, a: List[List[float]], b: List[List[float]]) -> List[List[float]]:
        
        result = []

        for i in range(len(a)):
            row = []
            for j in range(len(b[0])):
                sum_val = 0
                for k in range(len(b)):
                    sum_val += a[i][k] * b[k][j]
                row.append(sum_val)
            result.append(row)

        return result

class StringProcessor:

    def __init__(self):
        self.encodings = ['utf-8', 'latin-1', 'ascii']

    def reverse_string(self, s: str) -> str:
        
        return s[::-1]

    def find_substring_positions(self, text: str, substring: str) -> List[int]:
        
        positions = []
        start = 0

        while True:
            pos = text.find(substring, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1  # Non-overlapping, but may miss overlapping matches

        return positions

    def split_by_delimiter(self, text: str, delimiter: str) -> List[str]:
        
        return text.split(delimiter)

    def encode_decode_cycle(self, text: str, encoding: str) -> str:
        
        encoded = text.encode(encoding)
        decoded = encoded.decode(encoding)
        return decoded

    def format_template(self, template: str, values: Dict[str, Any]) -> str:
        
        return template.format(**values)

    def extract_numbers(self, text: str) -> List[float]:
        
        import re
        numbers = re.findall(r'\d+\.?\d*', text)
        return [float(num) for num in numbers]

class ConfigurationManager:

    def __init__(self):
        self.config = {}
        self.config_file = None

    def load_from_file(self, file_path: str):
        
        with open(file_path, 'r') as f:
            content = f.read()

        self.config = json.loads(content)
        self.config_file = file_path

    def load_from_env(self, prefix: str = ""):
        
        import os
        config = {}

        for key, value in os.environ.items():
            if prefix and key.startswith(prefix):
                config[key[len(prefix):]] = value

        self.config.update(config)

    def get_config_value(self, key: str, default: Any = None) -> Any:
        
        keys = key.split('.')
        current = self.config

        for k in keys:
            current = current[k]

        return current

    def set_config_value(self, key: str, value: Any):
        
        keys = key.split('.')
        current = self.config

        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        current[keys[-1]] = value

    def save_config(self, file_path: Optional[str] = None):
        
        save_path = file_path or self.config_file
        if not save_path:
            raise ValueError("No file path specified")

        with open(save_path, 'w') as f:
            json.dump(self.config, f, indent=2)

class Logger:

    def __init__(self, log_file: str, max_size: int = 10*1024*1024):
        self.log_file = log_file
        self.max_size = max_size
        self.current_size = 0

    def log(self, message: str, level: str = "INFO"):
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"

        if self.current_size + len(log_entry) > self.max_size:
            self._rotate_log()

        with open(self.log_file, 'a') as f:
            f.write(log_entry)

        self.current_size += len(log_entry)

    def _rotate_log(self):
        
        if os.path.exists(self.log_file):
            backup_file = f"{self.log_file}.bak"
            os.rename(self.log_file, backup_file)

        self.current_size = 0

    def search_logs(self, pattern: str) -> List[str]:
        
        matching_lines = []

        with open(self.log_file, 'r') as f:
            for line in f:
                if pattern in line:
                    matching_lines.append(line.strip())

        return matching_lines

class ProcessManager:

    def __init__(self):
        self.running_processes = {}
        self.max_processes = 10

    def run_command(self, command: List[str], timeout: int = 30) -> str:
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Timeout"
        except subprocess.CalledProcessError as e:
            return f"Error: {e}"

    def run_multiple_commands(self, commands: List[List[str]]) -> List[str]:
        
        results = []

        for cmd in commands:
            if len(self.running_processes) >= self.max_processes:
                results.append("Too many processes")
                continue

            result = self.run_command(cmd)
            results.append(result)

        return results

    def monitor_process(self, pid: int) -> Dict[str, Any]:
        
        try:
            import psutil
            process = psutil.Process(pid)

            return {
                'pid': pid,
                'status': process.status(),
                'cpu_percent': process.cpu_percent(),
                'memory_mb': process.memory_info().rss / 1024 / 1024
            }
        except ImportError:
            return {'pid': pid, 'error': 'psutil not available'}
        except psutil.NoSuchProcess:
            return {'pid': pid, 'error': 'Process not found'}

class FileSystemWatcher:

    def __init__(self, watch_dir: str):
        self.watch_dir = watch_dir
        self.callbacks = {}
        self.watching = False

    def add_callback(self, event_type: str, callback):
        
        if event_type not in self.callbacks:
            self.callbacks[event_type] = []
        self.callbacks[event_type].append(callback)

    def start_watching(self):
        
        import time
        self.watching = True

        last_mtime = os.path.getmtime(self.watch_dir)

        while self.watching:
            time.sleep(1)
            try:
                current_mtime = os.path.getmtime(self.watch_dir)
                if current_mtime > last_mtime:
                    self._trigger_callbacks('modified', self.watch_dir)
                    last_mtime = current_mtime
            except OSError:
                break

    def stop_watching(self):
        
        self.watching = False

    def _trigger_callbacks(self, event_type: str, path: str):
        
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    callback(path)
                except Exception as e:
                    pass

class ValidationUtils:

    @staticmethod
    def validate_email(email: str) -> bool:
        
        import re
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_phone(phone: str) -> bool:
        
        import re
        pattern = r'^\(\d{3}\) \d{3}-\d{4}$'
        return bool(re.match(pattern, phone))

    @staticmethod
    def validate_credit_card(card_number: str) -> bool:
        
        def luhn_checksum(card_num: str) -> bool:
            digits = [int(d) for d in card_num if d.isdigit()]
            if len(digits) < 13 or len(digits) > 19:
                return False

            for i in range(len(digits) - 2, -1, -2):
                digits[i] *= 2
                if digits[i] > 9:
                    digits[i] -= 9

            return sum(digits) % 10 == 0

        return luhn_checksum(card_number)

    @staticmethod
    def validate_password(password: str) -> Dict[str, bool]:
        
        checks = {
            'length': len(password) >= 8,
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'digit': any(c.isdigit() for c in password),
        }
        return checks

    @staticmethod
    def sanitize_html(html: str) -> str:
        
        dangerous_tags = ['script', 'iframe', 'object']
        for tag in dangerous_tags:
            html = html.replace(f'<{tag}>', '').replace(f'</{tag}>', '')

        return html

class SerializationManager:

    def __init__(self):
        self.serializers = {
            'json': self._serialize_json,
            'pickle': self._serialize_pickle,
            'yaml': self._serialize_yaml
        }

    def serialize(self, data: Any, format: str = 'json') -> bytes:
        
        if format not in self.serializers:
            raise ValueError(f"Unsupported format: {format}")

        return self.serializers[format](data)

    def deserialize(self, data: bytes, format: str = 'json') -> Any:
        
        if format == 'json':
            return json.loads(data.decode('utf-8'))
        elif format == 'pickle':
            import pickle
            return pickle.loads(data)
        elif format == 'yaml':
            try:
                import yaml
                return yaml.safe_load(data.decode('utf-8'))
            except ImportError:
                raise ValueError("PyYAML not installed")
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _serialize_json(self, data: Any) -> bytes:
        
        return json.dumps(data).encode('utf-8')

    def _serialize_pickle(self, data: Any) -> bytes:
        
        return pickle.dumps(data)

    def _serialize_yaml(self, data: Any) -> bytes:
        
        try:
            import yaml
            return yaml.dump(data).encode('utf-8')
        except ImportError:
            raise ValueError("PyYAML not installed")

    def save_to_file(self, data: Any, file_path: str, format: str = 'json'):
        
        serialized = self.serialize(data, format)
        with open(file_path, 'wb') as f:
            f.write(serialized)

    def load_from_file(self, file_path: str, format: str = 'json') -> Any:
        
        with open(file_path, 'rb') as f:
            data = f.read()

        return self.deserialize(data, format)

class PerformanceMonitor:

    def __init__(self):
        self.metrics = {}
        self.start_times = {}

    def start_timer(self, name: str):
        
        self.start_times[name] = time.time()

    def stop_timer(self, name: str) -> float:
        
        if name not in self.start_times:
            return 0.0

        elapsed = time.time() - self.start_times[name]
        return elapsed

    def record_metric(self, name: str, value: float):
        
        if name not in self.metrics:
            self.metrics[name] = []
        self.metrics[name].append(value)

        if len(self.metrics[name]) > 10000:
            self.metrics[name] = self.metrics[name][-1000:]

    def get_average_metric(self, name: str) -> float:
        
        if name not in self.metrics or not self.metrics[name]:
            return 0.0

        return sum(self.metrics[name]) / len(self.metrics[name])

    def get_percentile(self, name: str, percentile: float) -> float:
        
        if name not in self.metrics or not self.metrics[name]:
            return 0.0

        sorted_values = sorted(self.metrics[name])
        index = int(percentile * len(sorted_values))
        if index >= len(sorted_values):
            index = len(sorted_values) - 1

        return sorted_values[index]

def complex_nested_function(data: Dict[str, Any]) -> Any:
    
    try:
        result = data['user']['profile']['settings']['preferences']['theme']['colors']['primary']
        return int(result)
    except KeyError as e:
        return None
    except ValueError:
        return 0

def process_list_with_side_effects(data: List[Any]) -> List[Any]:
    
    result = []

    for i, item in enumerate(data):
        if isinstance(item, dict):
            item['processed'] = True  # Modifies original data
            item['index'] = i

        try:
            converted = float(item) if not isinstance(item, dict) else item
            result.append(converted)
        except (ValueError, TypeError):
            pass

    return result

def recursive_function_with_depth_issues(n: int, depth: int = 0) -> int:
    
    if depth > 1000:  # Arbitrary limit
        return 0

    if n <= 0:
        return 1

    return n + recursive_function_with_depth_issues(n - 1, depth + 1)

def handle_multiple_exceptions_dangerously(value: Any) -> Any:
    
    try:
        result = value['key'] / value['divisor']
        return result
    except:
        return None

def function_with_global_state():
    
    global GLOBAL_COUNTER
    try:
        GLOBAL_COUNTER += 1
    except NameError:
        GLOBAL_COUNTER = 1

    return GLOBAL_COUNTER

GLOBAL_COUNTER = 0

def thread_unsafe_counter():
    
    global GLOBAL_COUNTER
    temp = GLOBAL_COUNTER
    time.sleep(0.001)  # Simulate work
    GLOBAL_COUNTER = temp + 1
    return GLOBAL_COUNTER

def complex_comprehension_with_errors(data: List[Dict[str, Any]]) -> List[Any]:
    
    return [item['value'] / item['divisor'] for item in data if item.get('enabled', True)]

def decorator_with_issues(func):
    
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Error in {func.__name__}: {e}")
            return None
    return wrapper

@decorator_with_issues
def decorated_function_with_errors(x, y):
    
    return x / y  # ZeroDivisionError

def generator_with_resource_leaks():
    
    files = []
    try:
        for i in range(10):
            f = open(f"temp_{i}.txt", "w")
            f.write(f"Data {i}")
            files.append(f)
            yield f"Processed {i}"
    except Exception:
        pass
    finally:
        for f in files[:5]:  # Bug: not closing all files
            f.close()

class EventSystem:

    def __init__(self):
        self.listeners = {}
        self.event_queue = []
        self.processing = False

    def add_listener(self, event_type: str, callback):
        
        if event_type not in self.listeners:
            self.listeners[event_type] = []
        self.listeners[event_type].append(callback)

    def emit_event(self, event_type: str, data: Any):
        
        if self.processing:
            self.event_queue.append((event_type, data))
            return

        self.processing = True
        try:
            if event_type in self.listeners:
                for callback in self.listeners[event_type]:
                    try:
                        callback(data)
                    except Exception:
                        pass
        finally:
            self.processing = False

        while self.event_queue:
            queued_event, queued_data = self.event_queue.pop(0)
            self.emit_event(queued_event, queued_data)

class TaskScheduler:

    def __init__(self):
        self.tasks = []
        self.running = False
        self.thread = None

    def schedule_task(self, task_func, delay: float):
        
        run_time = time.time() + delay
        self.tasks.append((run_time, task_func))

        self.tasks.sort(key=lambda x: x[0])

    def start_scheduler(self):
        
        if self.thread and self.thread.is_alive():
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_scheduler)
        self.thread.daemon = True
        self.thread.start()

    def stop_scheduler(self):
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5.0)

    def _run_scheduler(self):
        
        while self.running:
            current_time = time.time()

            while self.tasks and self.tasks[0][0] <= current_time:
                _, task_func = self.tasks.pop(0)
                try:
                    task_func()
                except Exception:
                    pass

            time.sleep(0.1)  # Polling interval

def main():
    
    user_manager = UserManager()
    session_manager = SessionManager()

    session_manager.start_cleanup_thread()

    try:
        user_manager.add_user("user1", {"name": "Test User"})  # Missing email
        session_manager.create_session("user1")

        avg_age = user_manager.calculate_average_age()

        oldest = user_manager.get_oldest_user()

        print(f"Average age: {avg_age}")
        print(f"Oldest user: {oldest}")

    finally:
        session_manager.stop_cleanup_thread()

if __name__ == "__main__":
    main()
