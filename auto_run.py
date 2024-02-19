import os
import datetime
import time

def get_last_recorded_time():
    log_file = "time_log.txt"
    if os.path.exists(log_file):
        with open(log_file, 'r') as file:
            lines = file.readlines()
            last_end_time = lines[-1].strip() if lines else None

        if last_end_time:
            last_recorded_time = datetime.datetime.strptime(last_end_time, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            last_recorded_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
    else:
        last_recorded_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
    return last_recorded_time

while True:
    last_recorded_time = get_last_recorded_time()
    current_time = datetime.datetime.utcnow()
    time_difference = current_time - last_recorded_time

    if time_difference < datetime.timedelta(minutes=2):
        remaining_time = datetime.timedelta(minutes=2) - time_difference
        print(f"Waiting for {remaining_time} before next run.")
        time.sleep(remaining_time.total_seconds())
    os.system('python seam_file.py')


