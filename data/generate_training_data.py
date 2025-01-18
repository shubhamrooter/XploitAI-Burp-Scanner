import csv
import random

def generate_training_data(output_path):
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["request", "response", "label"])  # Header
        for _ in range(1000):
            request = f"GET /{random.randint(1, 1000)} HTTP/1.1"
            response = f"HTTP/1.1 200 OK\nContent-Length: {random.randint(10, 1000)}"
            label = random.choice(["safe", "vulnerable"])
            writer.writerow([request, response, label])