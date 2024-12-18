import pandas as pds
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import re
import numpy as np
from datetime import datetime
from time import process_time

current_year = datetime.now().year

isolationForest = IsolationForest(max_samples=1000, contamination=0.1)

def parse_logs(logfile):
    """
    Parse log file and extract timestamp, user, log level, and message.
    """
    logs = []

    with open(logfile, 'r') as file:
        for line in file:

            # Matches log format

            match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+(\w+):\s+(.*)', line)

            if match:
                # Extracts needed components from the log

                timestamp = match.group(1)
                user = match.group(2)
                log_level = match.group(3)  # Extract log level (e.g., INFO, ERROR)
                message = match.group(4)

                # Fixes an error I made in generate as a temp solution

                timestamp_with_year = f"{timestamp} {current_year}"

                # Parses timestamp

                try:
                    parsed_timestamp = pds.to_datetime(timestamp_with_year, format='%b %d %H:%M:%S %Y')
                except ValueError:
                    parsed_timestamp = pds.NaT

                # Appends to logs
                logs.append([parsed_timestamp, user, log_level, message])

    return pds.DataFrame(logs, columns=['Timestamp', 'User', 'LogLevel', 'Message'])



def calculate_threat_score(row):

    # Assigning threat score weights

    log_level_weights = {
        "INFO": 1,
        "DEBUG": 1,
        "WARN": 2,
        "ERROR": 3,
        "CRITICAL": 5
    }
    keywords_weights = {
        "error": 2,
        "unauthorized": 3,
        "crashed": 4,
        "panic": 5,
        "segmentation": 5,
        "memory": 4
    }

    # Base threat level from log level
    threat_score = log_level_weights.get(row['LogLevel'], 0)

    # Adds weights for keywords in the message
    for keyword, weight in keywords_weights.items():
        if keyword in row['Message'].lower():
            threat_score += weight

    return threat_score

def detect_anomalies(logfile):

    parsed_logs = parse_logs(logfile)

    # Drops rows with invalid timestamps as a failsafe
    parsed_logs = parsed_logs.dropna(subset=['Timestamp'])

    # Converts timestamps to Unix time
    parsed_logs['UnixTime'] = (parsed_logs['Timestamp'] - pds.Timestamp("1970-01-01")) // pds.Timedelta('1s')

    # Vectorizes messages
    vectorizer = TfidfVectorizer(max_features=100)
    message_features = vectorizer.fit_transform(parsed_logs['Message']).toarray()

    features = np.hstack((parsed_logs[['UnixTime']].fillna(0).values, message_features))

    # Uses Isolation Forest to detect anomalies
    isolationForest.fit(features)
    parsed_logs['Anomaly'] = isolationForest.predict(features)  # -1 for anomalies, 1 for normal

    # Calculates threat scores
    parsed_logs['ThreatScore'] = parsed_logs.apply(calculate_threat_score, axis=1)

    # Filters anomalies
    anomalies = parsed_logs[parsed_logs['Anomaly'] == -1]

    # Sorts by threat score
    prioritized_anomalies = anomalies.sort_values(by='ThreatScore', ascending=False)
    return prioritized_anomalies

def round_time_to_minute(df):
    df['RoundedTimestamp'] = df['Timestamp'].dt.floor('min')  # Round to nearest minute
    return df


def recommend_high_priority_anomalies(isolation_forest, n_recommendations=5):
    """
    Recommend the highest priority anomalies using Isolation Forest scores.
    """
    parsed_logs = parse_logs("mock_system_logs.log")

    # Prepare the data for Isolation Forest (e.g., numerical encoding of columns)
    numerical_data = pds.get_dummies(parsed_logs, columns=['LogLevel', 'User'], drop_first=True)
    numerical_data = numerical_data.drop(columns=['Timestamp', 'Message'])  # Drop non-numeric fields

    # Fit the Isolation Forest to the data
    isolation_forest.fit(numerical_data)

    # Compute anomaly scores (-1 for anomalies, 1 for normal)
    anomaly_scores = isolation_forest.decision_function(numerical_data)

    # Add the anomaly scores to the DataFrame
    parsed_logs['AnomalyScore'] = anomaly_scores

    # Sort by anomaly score (lowest scores indicate more anomalous data points)
    sorted_logs = parsed_logs.sort_values(by='AnomalyScore', ascending=True)

    # Select the top N anomalies
    recommendations = sorted_logs.head(n_recommendations)

    # Display recommendations
    print("Top High-Priority Anomalies for Analysis:")
    for index, row in recommendations.iterrows():
        print("------------------------------------------------------------")
        print(f"Timestamp: {row['Timestamp']}")
        print(f"User: {row['User']}")
        print(f"LogLevel: {row['LogLevel']}")
        print(f"Message: {row['Message']}")
        print(f"Anomaly Score: {row['AnomalyScore']}")
        print("------------------------------------------------------------")

    return recommendations


# Detects and prioritize anomalies
anomalies = detect_anomalies("mock_system_logs.log")

anomalies = round_time_to_minute(anomalies)

# Aggregates threat scores by rounded time
agg_anomalies = anomalies.groupby('RoundedTimestamp').agg({'ThreatScore': 'sum'}).reset_index()

# Displays top anomalies
print("Top Anomalies by Threat Level:")
print(anomalies[['Timestamp', 'User', 'LogLevel', 'Message', 'ThreatScore']])


# Recommends the top 5 high-priority anomalies
recommend_high_priority_anomalies(isolationForest, n_recommendations=5)

# Plots anomalies with threat levels
if not anomalies.empty:
    plt.figure(figsize=(12, 6))
    plt.hist(agg_anomalies['RoundedTimestamp'], bins=20, weights=agg_anomalies['ThreatScore'],
             histtype='step', color='red', linewidth=2, label='Threat Score (Stepped)')
    plt.xlabel('Time')
    plt.ylabel('Threat Score')
    plt.title('Stepped Histogram of Anomalies')
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()

    plt.show()


# Doesn't display anomalies if there aren't any
else:
    print("No anomalies detected.")

print(process_time(), "s")