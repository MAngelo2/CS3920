import random
from datetime import datetime, timedelta

def generate_mock_logs(file_path, num_entries=1000, num_anomalies=10, normal_ratio=0.7):

    log_levels = ["INFO", "WARN", "ERROR", "DEBUG"]
    users = ["systemd", "kernel", "cron", "sshd", "nginx"]
    normal_message = "Operation completed successfully."

    # Generic descriptions to attach to log messages
    other_messages = [
        "Started service successfully.",
        "Stopped service due to maintenance.",
        "User login successful.",
        "Connection closed by remote host.",
        "Scheduled task executed.",
    ]

    # Generic anomaly descriptions, can change to whatever
    anomalies = [
        "Disk read error at block 0xAA.",
        "Kernel panic: Unable to handle NULL pointer dereference.",
        "Unauthorized login attempt detected.",
        "Service crashed due to segmentation fault.",
        "High memory usage detected: 95% used.",
    ]

    normal_count = int(num_entries * normal_ratio)
    other_normal_count = num_entries - normal_count - num_anomalies

    with open(file_path, 'w') as log_file:
        current_time = datetime.now()

        # Generate completely normal log entries
        for _ in range(normal_count):
            timestamp = current_time.strftime("%b %d %H:%M:%S")
            user = random.choice(users)
            log_level = "INFO"
            log_file.write(f"{timestamp} {user} {log_level}: {normal_message}\n")
            current_time -= timedelta(seconds=random.randint(1, 10))

        # Generate other normal log entries
        for _ in range(other_normal_count):
            timestamp = current_time.strftime("%b %d %H:%M:%S")
            user = random.choice(users)
            log_level = random.choice(log_levels)
            message = random.choice(other_messages)
            log_file.write(f"{timestamp} {user} {log_level}: {message}\n")
            current_time -= timedelta(seconds=random.randint(1, 10))

        # Insert anomalies randomly
        for _ in range(num_anomalies):
            timestamp = current_time.strftime("%b %d %H:%M:%S")
            user = random.choice(users)
            log_level = "CRITICAL"
            message = random.choice(anomalies)
            log_file.write(f"{timestamp} {user} {log_level}: {message}\n")
            current_time -= timedelta(seconds=random.randint(1, 10))

    print(f"Mock log file generated at {file_path}")


# Generates a mock log file
generate_mock_logs("mock_system_logs.log")
