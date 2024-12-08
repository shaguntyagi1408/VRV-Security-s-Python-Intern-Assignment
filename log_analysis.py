import re
import csv
from collections import defaultdict

# Define the input log file and output CSV file
log_file = 'sample.log'
output_csv = 'log_analysis_results.csv'

# Threshold for detecting suspicious activity (failed login attempts)
FAILED_LOGIN_THRESHOLD = 10

# Regular expressions to extract required data
ip_pattern = r'^(\d{1,3}(?:\.\d{1,3}){3})'
endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE|OPTIONS) ([^ ]+)'
status_code_pattern = r'\" \d{3}'

# Initialize dictionaries for analysis
request_counts = defaultdict(int)
endpoint_counts = defaultdict(int)
failed_login_attempts = defaultdict(int)

# Process the log file
with open(log_file, 'r') as file:
    for line in file:
        # Extract IP address
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            ip = ip_match.group(1)
            request_counts[ip] += 1
        
        # Extract endpoint
        endpoint_match = re.search(endpoint_pattern, line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counts[endpoint] += 1
        
        # Detect failed login attempts (status code 401)
        if '401' in line or 'Invalid credentials' in line:
            if ip_match:
                ip = ip_match.group(1)
                failed_login_attempts[ip] += 1

# Analyze results
# Sort request counts by descending order
sorted_request_counts = sorted(request_counts.items(), key=lambda x: x[1], reverse=True)

# Identify the most accessed endpoint
most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])

# Detect suspicious activity
suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

# Display results
print("IP Address Requests:")
print("IP Address           Request Count")
for ip, count in sorted_request_counts:
    print(f"{ip:20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

print("\nSuspicious Activity Detected:")
print("IP Address           Failed Login Attempts")
for ip, count in suspicious_ips.items():
    print(f"{ip:20} {count}")

# Save results to CSV
with open(output_csv, 'w', newline='') as csv_file:
    writer = csv.writer(csv_file)
    # Write IP requests
    writer.writerow(['IP Address', 'Request Count'])
    writer.writerows(sorted_request_counts)
    writer.writerow([])  # Empty row for separation

    # Write most accessed endpoint
    writer.writerow(['Most Accessed Endpoint', 'Access Count'])
    writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
    writer.writerow([])

    # Write suspicious activity
    writer.writerow(['Suspicious Activity Detected'])
    writer.writerow(['IP Address', 'Failed Login Attempts'])
    for ip, count in suspicious_ips.items():
        writer.writerow([ip, count])

print(f"\nResults saved to {output_csv}")
