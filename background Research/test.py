import os
import time
import datetime

x = 3

while True:
    start_time = datetime.datetime.now()  # Record start time
    os.system('python copy_seams_db.py')
    end_time = datetime.datetime.now()  # Record end time

    total_processing_time = end_time - start_time  # Calculate processing time
    print(f"Total processing time: {total_processing_time}")

    time.sleep(10)
    print(datetime.datetime.now())
    x -= 1
    if x == 0:
        break
