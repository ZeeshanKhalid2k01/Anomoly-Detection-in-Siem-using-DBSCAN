from sklearn.preprocessing import LabelEncoder
from datetime import datetime, timedelta
import requests
import pandas as pd
import numpy as np
import os.path
import joblib

from urllib3.exceptions import InsecureRequestWarning
# Disable the warning about unverified HTTPS requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set INITIAL TIME & END TIME
INITIAL_TIME = 0
END_TIME = 0

# Set ELASTICSEARCH_URL, ES_USERNAME, ES_PASSWORD
ELASTICSEARCH_URL = "https://192.168.7.2:9200"
ES_USERNAME = "elastic"
ES_PASSWORD = "ncsael@123"
INDEX_NAME = "siem-*"






def add_new_time_values():
    
    # def reset_time():
    #     global INITIAL_TIME
    #     global END_TIME
        
    #     if(INITIAL_TIME != 0):
    #         INITIAL_TIME = END_TIME

    #     else:
    #         last_timestamp = datetime.utcnow() - timedelta(minutes=2)
    #         INITIAL_TIME = last_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
    #     current_time = datetime.utcnow()
    #     END_TIME = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # reset_time()
    # print(INITIAL_TIME)
    # print(END_TIME)

    def reset_time():
        global INITIAL_TIME
        global END_TIME
        log_file = "time_log.txt"  # File to store start and end times

        if os.path.exists(log_file):
            # Read the last recorded end time from the log file
            with open(log_file, 'r') as file:
                lines = file.readlines()
                last_end_time = lines[-1].strip() if lines else None

            if last_end_time:
                start_time = datetime.strptime(last_end_time, "%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                start_time = datetime.utcnow() - timedelta(minutes=2)
        else:
            start_time = datetime.utcnow() - timedelta(minutes=2)

        end_time = start_time + timedelta(minutes=2)

        # Store the end time in the log file for future reference
        with open(log_file, 'a') as file:
            file.write(end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ") + "\n")

        INITIAL_TIME = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        END_TIME = end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    reset_time()    



    def find_hits():
        global INITIAL_TIME
        global END_TIME
        global ELASTICSEARCH_URL
        global ES_USERNAME
        global ES_PASSWORD

        url = f"{ELASTICSEARCH_URL}/siem-*/_search"
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": INITIAL_TIME,
                        "lte": END_TIME
                    }
                }
            }
        }

        try:
            response = requests.get(url, auth=(ES_USERNAME, ES_PASSWORD), headers=headers, json=payload, verify=False)
            if response.status_code == 200:
                logs = response.json()
                total_logs = logs["hits"]["total"]["value"] if "hits" in logs else 0
                # print(f"Total new logs since {INITIAL_TIME}: {total_logs}")
                return total_logs
            else:
                print("Failed to fetch logs.")
        except Exception as e:
            print(f"Failed to connect: {e}")

    # print(find_hits())

    def add_data(hits):
        global INITIAL_TIME
        global END_TIME
        global ELASTICSEARCH_URL
        global ES_USERNAME
        global ES_PASSWORD
        global INDEX_NAME

        url = f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search"
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc",
                        "format": "strict_date_optional_time",
                        "unmapped_type": "boolean"
                    }
                },
                {
                    "_doc": {
                        "order": "desc",
                        "unmapped_type": "boolean"
                    }
                }
            ],
            "track_total_hits": False,
            "fields": [
                {
                    "field": "*",
                    "include_unmapped": "true"
                },
                {
                    "field": "@timestamp",
                    "format": "strict_date_optional_time"
                },
                {
                    "field": "BeginTime",
                    "format": "strict_date_optional_time"
                },
                {
                    "field": "EndTime",
                    "format": "strict_date_optional_time"
                },
                {
                    "field": "Time",
                    "format": "strict_date_optional_time"
                }
            ],
            "size": hits,
            "version": True,
            "script_fields": {},
            "stored_fields": ["*"],
            "runtime_mappings": {},
            "_source": False,
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "format": "strict_date_optional_time",
                                    "gte": INITIAL_TIME,
                                    "lte": END_TIME
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            },
            "highlight": {
                "pre_tags": ["@kibana-highlighted-field@"],
                "post_tags": ["@/kibana-highlighted-field@"],
                "fields": {"*": {}},
                "fragment_size": 2147483647
            }
        }

        response = requests.get(url, auth=(ES_USERNAME, ES_PASSWORD), headers=headers, json=payload, verify=False)
        
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Failed to fetch logs."}

    # Call the function to fetch logs
    logs = add_data(find_hits())


        

    # Check if logs were fetched successfully
    if "error" not in logs:
        hits = logs.get("hits", {}).get("hits", [])
        
        # Extracting fields from hits
        data = [hit.get("fields", {}) for hit in hits]

        # Create DataFrame
        df_logs = pd.DataFrame(data)
        return df_logs
    




def create_db():
    #check if seam_logs.db exist or not
    if os.path.exists('seam_logs.db'):
        print("Database already exists.")
    else:
        print("Creating database...")
        import sqlite3

        # Connect to a database (will create a new one if it doesn't exist)
        conn = sqlite3.connect('seam_logs.db')

        # Create a cursor object to execute SQL commands
        cursor = conn.cursor()

        # SQL command to create a table
        create_table_query = '''
        CREATE TABLE IF NOT EXISTS seam_table (
            Action INTEGER,
            Application INTEGER,
            Attack INTEGER,
            Category INTEGER,
            CloseReason INTEGER,
            Cpu REAL,
            "Destination-address" INTEGER,
            "Destination-port" REAL,
            "Destination-vpn-id" REAL,
            "Destination-zone" INTEGER,
            DstLocation INTEGER,
            EventNum REAL,
            "IP-address" INTEGER,
            IPVer REAL,
            MaxSpeed REAL,
            ModuleBrief INTEGER,
            ModuleName INTEGER,
            Os INTEGER,
            Policy INTEGER,
            "Policy-name" INTEGER,
            Priority TEXT,
            Profile INTEGER,
            "Protocol-Name" INTEGER,
            "Protocol-Number" REAL,
            RcvBytes INTEGER,
            RcvPkts INTEGER,
            RecieveInterface INTEGER,
            Role REAL,
            SendBytes INTEGER,
            SendPkts INTEGER,
            Severity TEXT,
            SignId REAL,
            SignName INTEGER,
            "Source-address" INTEGER,
            "Source-vpn-id" REAL,
            "Source-zone" INTEGER,
            SrcLocation INTEGER,
            SyslogId INTEGER,
            Target INTEGER,
            TotalPackets REAL,
            UserName INTEGER,
            VSys INTEGER,
            slot INTEGER,
            Processed REAL,
            DayOfTheWeek INTEGER,
            DayOrNight INTEGER,
            TimeBins INTEGER
        );
        '''

        # Execute the SQL command to create the table
        cursor.execute(create_table_query)

        # Commit changes and close connection
        conn.commit()
        conn.close()





def filter_required_cols(df_logs):
    # Assuming df_logs is your DataFrame
    required_columns = [
        "@timestamp", "Action", "Application", "Attack", "BeginTime", "Category", "CloseReason", "Cpu",
        "Destination-address", "Destination-port", "Destination-vpn-id", "Destination-zone", "DstLocation",
        "EndTime", "EventNum", "IPVer", "MaxSpeed", "ModuleBrief", "ModuleName", "Os", "Policy",
        "Policy-name", "Priority", "Profile", "Protocol-Name", "Protocol-Number", "RcvBytes", "RcvPkts",
        "RecieveInterface", "Role", "SendBytes", "SendPkts", "Severity", "SignId", "SignName", "Source-address",
        "Source-vpn-id", "Source-zone", "SrcLocation", "SyslogId", "Target", "TotalPackets", "UserName", "VSys", "slot"
    ]

    missing_columns = [col for col in required_columns if col not in df_logs.columns]

    if missing_columns:
        print(f"The following columns are missing: {', '.join(missing_columns)}")

        # Add missing columns with NaN values to the DataFrame
        for col in missing_columns:
            df_logs[col] = np.nan

        df_logs = df_logs[required_columns]
    else:
        print("All required columns are present in the DataFrame.")
        df_logs = df_logs[required_columns]
    
    return df_logs





def clean_value_special_symbols(value):
    return str(value).replace("[", "").replace("]", "").replace("'", "").replace("nan", "-")





def transforming_columns(df_logs):
    def read_mapping(column_name):
        mapping_dir = 'mapping'
        mapping_file = os.path.join(mapping_dir, f'{column_name}_mapping.txt')
        if not os.path.exists(mapping_file):
            os.makedirs(mapping_dir, exist_ok=True)
            with open(mapping_file, 'w') as file:
                file.write('{}')
        with open(mapping_file, 'r') as file:
            return eval(file.read())

    def write_mapping(column_name, column_mapping):
        mapping_dir = 'mapping'
        mapping_file = os.path.join(mapping_dir, f'{column_name}_mapping.txt')
        with open(mapping_file, 'w') as file:
            file.write(str(column_mapping))

    def transform_column(column_name):
        column_mapping = read_mapping(column_name)
        modified = False  # Flag to track if mapping has been modified

        def assign_unique_number(value):
            nonlocal column_mapping, modified
            if value not in column_mapping:
                unique_number = max(column_mapping.values()) + 1 if column_mapping else 0
                column_mapping[value] = unique_number
                modified = True  # Set flag when a new value is encountered
            return column_mapping[value]

        df_logs[column_name] = df_logs[column_name].apply(assign_unique_number)

        # Write the mapping only if it has been modified
        if modified:
            write_mapping(column_name, column_mapping)

    # Apply transformation to each column
    columns_to_transform = [
            'Attack', 'Category', 'DstLocation', 'Os', 'SignName', 'SrcLocation', 'Target',
            'UserName', 'VSys', 'slot', 'Action', 'Policy', 'Profile', 'Protocol-Name',
            'Application', 'Source-zone', 'CloseReason', 'Destination-zone', 'ModuleName',
            'ModuleBrief', 'RecieveInterface', 'Policy-name'
        ]
    for column in columns_to_transform:
        transform_column(column)
    
    return df_logs





def transform_ip(ip):
    if ip == '-':
        return -1  # Label '-' as -1
    elif ip.startswith('192.168'):
        return 0  # IP starts with 192.168
    else:
        # Remove dots from IP and divide by a hardcoded value (e.g., 10^12)
        return int(ip.replace('.', '')) / 1e12





def replace_values_and_convert_to_numeric1(df):
    columns = [
    'Cpu',
    'Destination-vpn-id',
    'EventNum',
    'IPVer',
    'MaxSpeed',
    'Role',
    'SignId',
    'Source-vpn-id',
    'Protocol-Number',
    'TotalPackets',
    'Destination-port',
    'SendBytes',
    'SendPkts',
    'RcvBytes',
    'RcvPkts',
    'SyslogId',
    'Severity',
    'Priority'
    ]
    for col in columns:
        df[col] = df[col].astype(str)
        df[col] = df[col].replace('-', '-0.1')
        df[col] = pd.to_numeric(df[col], errors='coerce')





def find_processed_time(df_logs):
    # Replace '-' with a default date in ISO 8601 Zulu format
    default_date = '1970-01-01T00:00:00.000Z'
    df_logs['BeginTime'] = df_logs['BeginTime'].replace('-', default_date)
    df_logs['EndTime'] = df_logs['EndTime'].replace('-', default_date)

    # Convert 'EndTime' and 'BeginTime' columns to datetime format
    df_logs['EndTime'] = pd.to_datetime(df_logs['EndTime'])
    df_logs['BeginTime'] = pd.to_datetime(df_logs['BeginTime'])

    # Calculate time difference in seconds and store in a new 'Processed' column
    df_logs['Processed'] = (df_logs['EndTime'] - df_logs['BeginTime']).dt.total_seconds()

    # Drop 'BeginTime' and 'EndTime' columns
    df_logs = df_logs.drop(columns=['BeginTime', 'EndTime'])
    return(df_logs)




def dig_timestamps(df_logs):
    import pandas as pd

    # Convert to datetime format (Zulu time format)
    df_logs['@timestamp'] = pd.to_datetime(df_logs['@timestamp'])

    # Extracting day of the week
    df_logs['DayOfTheWeek'] = df_logs['@timestamp'].dt.dayofweek  # Numeric representation of day of the week (0 - Monday, 6 - Sunday)

    # Extracting time of the day
    bins = {
        (0, 6): 0,      # Night
        (6, 12): 1,     # Morning
        (12, 18): 2,    # Afternoon
        (18, 24): 3     # Evening
    }
    df_logs['DayOrNight'] = df_logs['@timestamp'].dt.hour.apply(lambda x: next((v for k, v in bins.items() if k[0] <= x < k[1]), 0))

    # Extracting time bins
    bins_labels = ['Late Night', 'Early Morning', 'Morning', 'Afternoon', 'Evening', 'Night']
    bins_edges = [0, 4, 8, 12, 16, 20, 24]  # Customize as needed
    df_logs['TimeBins'] = pd.cut(df_logs['@timestamp'].dt.hour, bins=bins_edges, labels=False)

    df_logs = df_logs.drop(columns=['@timestamp'])
    return(df_logs)





def append_db(df_logs):
    import pandas as pd
    import sqlite3

    # Assuming df_logs is your DataFrame containing the data you want to append to the SQL database
    # And the database file is 'seam_logs.db'

    # Connect to the SQLite database
    conn = sqlite3.connect('seam_logs.db')

    # Append the data from df_logs to the SQL database table 'seam_table'
    df_logs.to_sql('seam_table', conn, if_exists='append', index=False)

    # Commit changes and close connection
    conn.commit()
    conn.close()



create_db()#1
df_logs=add_new_time_values().copy()#2
df_logs=filter_required_cols(df_logs).copy()#3
df_logs = df_logs.applymap(clean_value_special_symbols)#4
df_logs['Destination-address'] = df_logs['Destination-address'].apply(transform_ip)
df_logs['Source-address'] = df_logs['Source-address'].apply(transform_ip)
df_logs = transforming_columns(df_logs).copy()#6
replace_values_and_convert_to_numeric1(df_logs)#6
df_logs=find_processed_time(df_logs).copy()#8
df_logs=dig_timestamps(df_logs).copy()#9
append_db(df_logs)#10
    


# run functions after every 2 minute
    


# import time
# from tqdm import tqdm

# loop = 0
# while True:
#     create_db()#1
#     df_logs=add_new_time_values().copy()#2
#     df_logs=filter_required_cols(df_logs).copy()#3
#     df_logs = df_logs.applymap(clean_value_special_symbols)#4
#     df_logs['Destination-address'] = df_logs['Destination-address'].apply(transform_ip)
#     df_logs['Source-address'] = df_logs['Source-address'].apply(transform_ip)
#     df_logs = transforming_columns(df_logs).copy()#6
#     replace_values_and_convert_to_numeric1(df_logs)#6
#     df_logs=find_processed_time(df_logs).copy()#8
#     df_logs=dig_timestamps(df_logs).copy()#9
#     append_db(df_logs)#10

#     for _ in tqdm(range(120), desc="Waiting", unit="s"):
#         time.sleep(1)

#     # Print loop number after waiting
#     print("loop", loop + 1)
#     loop += 1


