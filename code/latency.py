import time
import sys

def simulate_network_conditions(data, latency_ms, bandwidth_mbps):
    """
    Simulates network conditions by introducing latency and limiting bandwidth.

    :param data: The data to be "sent" (multidimensional data or a polynomial).
    :param latency_ms: The round-trip latency in milliseconds.
    :param bandwidth_mbps: The bandwidth in Megabits per second.
    """
    # Convert latency to seconds and bandwidth to bytes per second
    latency_sec = latency_ms / 1000.0
    bandwidth_bps = (bandwidth_mbps * 1024 * 1024) / 8

    # Calculate total size of the data in bytes (assuming data is a bytes object or similar)
    total_data_size = sys.getsizeof(data)

    # Calculate the time it takes to send the data at the given bandwidth
    time_to_send = total_data_size / bandwidth_bps

    # Simulate sending data in chunks
    chunk_size = bandwidth_bps * 0.1  # Adjust chunk size as needed
    bytes_sent = 0

    while bytes_sent < total_data_size:
        # Simulate sending a chunk of data
        bytes_to_send = min(chunk_size, total_data_size - bytes_sent)
        bytes_sent += bytes_to_send

        # Simulate the delay to send this chunk at the specified bandwidth
        time.sleep(time_to_send * (bytes_to_send / total_data_size))

    # Simulate round-trip latency at the end
    time.sleep(latency_sec)
    return total_data_size


