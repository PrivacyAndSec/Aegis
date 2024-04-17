from Test_server import Aggregator
from Test_client import User
import threading


def main():
    # Initialization code...

    aggregator = Aggregator()
    # Start the server in a new thread
    server_thread = threading.Thread(target=aggregator.start_server)
    server_thread.start()

    users = [User() for i in range(2)]

    # Assuming you have some data to send from each user
    for user in users:
        user_data = "Some data"
        user.communicate_with_server(user_data)


    for user in users:
        user_data = "Some data123123"
        user.communicate_with_server(user_data)


if __name__ == "__main__":
    main()
