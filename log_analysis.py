import csv
import re
from collections import defaultdict

# Constants
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """
    Parse the log file and return the logs as a list of lines.
    """
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_lines):
    """
    Count the number of requests made by each IP address.
    """
    ip_count = defaultdict(int)
    for line in log_lines:
        # Regular expression to extract IP address from log line
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            ip_count[ip] += 1
    return ip_count

def identify_most_accessed_endpoint(log_lines):
    """
    Identify the most frequently accessed endpoint in the logs.
    """
    endpoint_count = defaultdict(int)
    for line in log_lines:
        # Regular expression to extract endpoint from log line
        match = re.search(r'\"[A-Z]+\s(/[^"]+)', line)
        if match:
            endpoint = match.group(1)
            endpoint_count[endpoint] += 1
    # Find the most accessed endpoint
    most_accessed_endpoint = max(endpoint_count, key=endpoint_count.get, default=None)
    return most_accessed_endpoint, endpoint_count[most_accessed_endpoint]

def detect_suspicious_activity(log_lines, threshold=FAILED_LOGIN_THRESHOLD):
    """
    Detect suspicious activity (failed login attempts).
    """
    failed_logins = defaultdict(int)
    for line in log_lines:
        # Check for failed login attempts (HTTP status code 401)
        if '401' in line or 'Invalid credentials' in line:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1
    # Filter IPs exceeding the failed login threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return suspicious_ips

def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file="log_analysis_results.csv"):
    """
    Save the results to a CSV file.
    """
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP Address section
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint section
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity section
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def display_results(ip_requests, most_accessed_endpoint, suspicious_activity):
    """
    Display the results in a clear, organized format in the terminal.
    """
    # Display Requests per IP Address
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:20} {count}")

    # Display Most Accessed Endpoint
    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    # Display Suspicious Activity
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")

def main():
    # Path to your log file
    log_file_path = 'access.log'  # Replace with the path to your log file
    
    # Parse the log file
    log_lines = parse_log_file(log_file_path)
    
    # Count requests per IP
    ip_requests = count_requests_per_ip(log_lines)
    
    # Identify most accessed endpoint
    most_accessed_endpoint = identify_most_accessed_endpoint(log_lines)
    
    # Detect suspicious activity (failed login attempts)
    suspicious_activity = detect_suspicious_activity(log_lines)
    
    # Save results to CSV
    save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity)
    
    # Display results in the terminal
    display_results(ip_requests, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()
