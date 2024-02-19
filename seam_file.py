def add_new_time_values():

    global DF
   

    # def reset_time():
    #     global INITIAL_TIME
    #     global END_TIME
    #     log_file = "time_log.txt"  # File to store start and end times

    #     if os.path.exists(log_file):
    #         # Read the last recorded end time from the log file
    #         with open(log_file, 'r') as file:
    #             lines = file.readlines()
    #             last_end_time = lines[-1].strip() if lines else None

    #         if last_end_time:
    #             start_time = datetime.strptime(last_end_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    #         else:
    #             start_time = datetime.utcnow() - timedelta(minutes=2)
    #     else:
    #         start_time = datetime.utcnow() - timedelta(minutes=2)

    #     end_time = start_time + timedelta(minutes=2)

    #     # Store the end time in the log file for future reference
    #     with open(log_file, 'a') as file:
    #         file.write(end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ") + "\n")

    #     INITIAL_TIME = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    #     END_TIME = end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # reset_time()    

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

        current_time = datetime.utcnow()
        elapsed_time = current_time - start_time

        # Adjust end time based on elapsed time
        if elapsed_time > timedelta(minutes=3):
            end_time = start_time + timedelta(minutes=3)
            print("Time elapsed is greater than 3 minutes. Adjusting end time to 3 minutes from start time.")
        else:
            end_time = start_time + timedelta(minutes=2)
            print("Time elapsed is less than 3 minutes. Adjusting end time to 2 minutes from start time.")

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
        # data = [hit.get("fields", {}) for hit in hits]
        data = [{"_id": hit.get("_id"), **hit.get("fields", {})} for hit in hits]


        # Create DataFrame
        df_logs = pd.DataFrame(data)
        DF = df_logs.copy()
        return df_logs
    




def add_new_time_values():

    global DF
   

    # def reset_time():
    #     global INITIAL_TIME
    #     global END_TIME
    #     log_file = "time_log.txt"  # File to store start and end times

    #     if os.path.exists(log_file):
    #         # Read the last recorded end time from the log file
    #         with open(log_file, 'r') as file:
    #             lines = file.readlines()
    #             last_end_time = lines[-1].strip() if lines else None

    #         if last_end_time:
    #             start_time = datetime.strptime(last_end_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    #         else:
    #             start_time = datetime.utcnow() - timedelta(minutes=2)
    #     else:
    #         start_time = datetime.utcnow() - timedelta(minutes=2)

    #     end_time = start_time + timedelta(minutes=2)

    #     # Store the end time in the log file for future reference
    #     with open(log_file, 'a') as file:
    #         file.write(end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ") + "\n")

    #     INITIAL_TIME = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    #     END_TIME = end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # reset_time()    

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

        current_time = datetime.utcnow()
        elapsed_time = current_time - start_time

        # Adjust end time based on elapsed time
        if elapsed_time > timedelta(minutes=3):
            end_time = start_time + timedelta(minutes=3)
            print("Time elapsed is greater than 3 minutes. Adjusting end time to 3 minutes from start time.")
        else:
            end_time = start_time + timedelta(minutes=2)
            print("Time elapsed is less than 3 minutes. Adjusting end time to 2 minutes from start time.")

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
        # data = [hit.get("fields", {}) for hit in hits]
        data = [{"_id": hit.get("_id"), **hit.get("fields", {})} for hit in hits]


        # Create DataFrame
        df_logs = pd.DataFrame(data)
        DF = df_logs.copy()
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





def dbscan(df_logs):
    global DF
    # Check for NaN, null, or inf in the entire DataFrame
    problematic_values = df_logs.isnull().values.any() or df_logs.isna().values.any() or df_logs.isin([np.inf, -np.inf]).values.any()

    if problematic_values:
        print("The DataFrame contains NaN, null, or infinite values.")
    else:
        print("The DataFrame does not contain NaN, null, or infinite values.")
        from sklearn.cluster import DBSCAN

        # Assuming df2 contains your DataFrame with all the columns
        X = df_logs.values  # Using all columns as features

        # Initialize DBSCAN
        dbscan = DBSCAN(eps=0.5, min_samples=5)  # Adjust parameters as needed

        # Fit DBSCAN to your data
        dbscan.fit(X)

        # Retrieve cluster labels and outliers
        labels = dbscan.labels_
        outliers = df_logs[labels == -1]  # Outliers are labeled as -1
        DF['dbscan'] = dbscan.labels_




def send2Elastic():
    import pandas as pd
    global DF
    
    # Assuming your DataFrame is named 'DF'
    DF.rename(columns={"_id": "log_id"}, inplace=True)
    DF.rename(columns={"dbscan": "results"}, inplace=True)
    
    columns_to_extract = [
    "@timestamp", "@version", "@version.keyword", "Action", "Action.keyword",
    "Application", "Application.keyword", "ApplicationName", "ApplicationName.keyword",
    "Attack", "Attack.keyword", "BeginTime", "Category", "Category.keyword",
    "CloseReason", "CloseReason.keyword", "Cpu", "Cpu.keyword", "Destination-address",
    "Destination-address.keyword", "Destination-port", "Destination-port.keyword",
    "Destination-vpn-id", "Destination-vpn-id.keyword", "Destination-zone",
    "Destination-zone.keyword", "DstLocation", "DstLocation.keyword", "EndTime",
    "EventNum", "EventNum.keyword", "HostName", "HostName.keyword", "IP-address",
    "IP-address.keyword", "IPVer", "IPVer.keyword", "MaxSpeed", "MaxSpeed.keyword",
    "ModuleBrief", "ModuleBrief.keyword", "ModuleName", "ModuleName.keyword", "Os",
    "Os.keyword", "Policy", "Policy-name", "Policy-name.keyword", "Policy.keyword",
    "Priority", "Priority.keyword", "Profile", "Profile.keyword", "Protocol-Name",
    "Protocol-Name.keyword", "Protocol-Number", "RcvBytes", "RcvPkts",
    "RecieveInterface", "RecieveInterface.keyword", "Role", "Role.keyword",
    "SendBytes", "SendPkts", "Severity", "SignId", "SignId.keyword", "SignName",
    "SignName.keyword", "Source-address", "Source-address.keyword", "Source-nat-address",
    "Source-nat-address.keyword", "Source-nat-port", "Source-nat-port.keyword",
    "Source-port", "Source-port.keyword", "Source-vpn-id", "Source-vpn-id.keyword",
    "Source-zone", "Source-zone.keyword", "SrcLocation", "SrcLocation.keyword",
    "SyslogId", "SyslogId.keyword", "Target", "Target.keyword", "Time", "TotalPackets",
    "UserName", "UserName.keyword", "VSys", "VSys.keyword", "_id", "_index",
    "_score", "event.original", "event.original.keyword", "host.ip", "host.ip.keyword",
    "message", "message.keyword", "slot", "slot.keyword", "log_id", "results"
    ]
    # Create an empty DataFrame with columns from columns_to_extract
    DF2 = pd.DataFrame(columns=columns_to_extract)

    # Check and fill missing columns with '-'
    for col in columns_to_extract:
        if col not in DF.columns:
            DF2[col] = '-'
        else:
            DF2[col] = DF[col].fillna('-')

    DF2 = DF2[DF2['results'] == -1].copy()

    DF2.replace([pd.NA, None, np.inf, -np.inf, pd.np.nan], '-', inplace=True)

    columns_total = [
    "@version", "@version.keyword", "Action", "Action.keyword",
    "Application", "Application.keyword", "ApplicationName", "ApplicationName.keyword",
    "Attack", "Attack.keyword", "BeginTime", "Category", "Category.keyword",
    "CloseReason", "CloseReason.keyword", "Cpu", "Cpu.keyword", "Destination-address",
    "Destination-address.keyword", "Destination-port", "Destination-port.keyword",
    "Destination-vpn-id", "Destination-vpn-id.keyword", "Destination-zone",
    "Destination-zone.keyword", "DstLocation", "DstLocation.keyword", "EndTime",
    "EventNum", "EventNum.keyword", "HostName", "HostName.keyword", "IP-address",
    "IP-address.keyword", "IPVer", "IPVer.keyword", "MaxSpeed", "MaxSpeed.keyword",
    "ModuleBrief", "ModuleBrief.keyword", "ModuleName", "ModuleName.keyword", "Os",
    "Os.keyword", "Policy", "Policy-name", "Policy-name.keyword", "Policy.keyword",
    "Priority", "Priority.keyword", "Profile", "Profile.keyword", "Protocol-Name",
    "Protocol-Name.keyword", "Protocol-Number", "RcvBytes", "RcvPkts",
    "RecieveInterface", "RecieveInterface.keyword", "Role", "Role.keyword",
    "SendBytes", "SendPkts", "Severity", "SignId", "SignId.keyword", "SignName",
    "SignName.keyword", "Source-address", "Source-address.keyword", "Source-nat-address",
    "Source-nat-address.keyword", "Source-nat-port", "Source-nat-port.keyword",
    "Source-port", "Source-port.keyword", "Source-vpn-id", "Source-vpn-id.keyword",
    "Source-zone", "Source-zone.keyword", "SrcLocation", "SrcLocation.keyword",
    "SyslogId", "SyslogId.keyword", "Target", "Target.keyword", "Time", "TotalPackets",
    "UserName", "UserName.keyword", "VSys", "VSys.keyword", "_id", "_index",
    "_score", "event.original", "event.original.keyword", "host.ip", "host.ip.keyword",
    "message", "message.keyword", "slot", "slot.keyword", "log_id", "results", "@timestamp"
    ]
    
    columns_without_keyword = [col for col in columns_total if not col.endswith('.keyword')]

    DF2 = DF2[columns_without_keyword].copy()

    # Replace NaN with 'not-specified' and other specific values like 'null', 'inf', and '-'
    values_to_replace = ['null', 'inf', '-']
    replacement_value = 'not-specified'

    columns_without_keyword = columns_without_keyword[:-3]


    for col in columns_without_keyword:
        # Fill NaN values with 'not-specified'
        DF2[col].fillna(replacement_value, inplace=True)
        
        # Replace other specific values
        DF2[col] = DF2[col].replace({val: replacement_value for val in values_to_replace})


    from elasticsearch import Elasticsearch, helpers
    import pandas as pd

    # Your Elasticsearch details
    # ELASTICSEARCH_URL = "https://192.168.7.2:9200"
    ELASTICSEARCH_URL = "https://192.168.7.100:9200"
    ES_USERNAME = "elastic"
    ES_PASSWORD = "ncsael@123"

    # Create an Elasticsearch connection
    es_client = Elasticsearch([ELASTICSEARCH_URL], http_auth=(ES_USERNAME, ES_PASSWORD), verify_certs=False)

    # Index name to append data
    index_name = "anamoly_table"  # Use the existing index name

    # Check if the index exists
    if not es_client.indices.exists(index=index_name):
        # Define the index settings and mappings for log_id, results, @timestamp, and attack columns
        index_settings = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "log_id": {"type": "keyword"},
                    "@timestamp": {"type": "date"},
                    "@version": {"type": "keyword"},
                    "Action": {"type": "keyword"},
                    "Application": {"type": "keyword"},
                    "Attack": {"type": "keyword"},
                    "BeginTime": {"type": "keyword"},
                    "Catagory": {"type": "keyword"},
                    "CloseReason": {"type": "keyword"},
                    "Cpu": {"type": "keyword"},
                    "Destination-address": {"type": "keyword"},
                    "Destination-port": {"type": "keyword"},
                    "Destination-vpn-id": {"type": "keyword"},
                    "Destination-zone": {"type": "keyword"},
                    "DstLocation": {"type": "keyword"},
                    "EndTime": {"type": "keyword"},
                    "HostName": {"type": "keyword"},
                    "IP-address": {"type": "keyword"},
                    "IPVer": {"type": "keyword"},
                    "MaxSpeed": {"type": "keyword"},
                    "ModuleBrief": {"type": "keyword"},
                    "ModuleName": {"type": "keyword"},
                    "Os": {"type": "keyword"},
                    "Policy": {"type": "keyword"},
                    "Policy-name": {"type": "keyword"},
                    "Priority": {"type": "keyword"},
                    "Profile": {"type": "keyword"},
                    "Protocol-Name": {"type": "keyword"},
                    "Protocol-Number": {"type": "keyword"},
                    "RcvBytes": {"type": "keyword"},
                    "RcvPkts": {"type": "keyword"},
                    "RecieveInterface": {"type": "keyword"},
                    "Role": {"type": "keyword"},
                    "SendBytes": {"type": "keyword"},
                    "SendPkts": {"type": "keyword"},
                    "Severity": {"type": "keyword"},
                    "SignId": {"type": "keyword"},
                    "SignName": {"type": "keyword"},
                    "Source-address": {"type": "keyword"},
                    "Source-nat-address": {"type": "keyword"},
                    "Source-nat-port": {"type": "keyword"},
                    "Source-port": {"type": "keyword"},
                    "Source-vpn-id": {"type": "keyword"},
                    "Source-zone": {"type": "keyword"},
                    "SrcLocation": {"type": "keyword"},
                    "SyslogId": {"type": "keyword"},
                    "Target": {"type": "keyword"},
                    "Time": {"type": "keyword"},
                    "TotalPackets": {"type": "keyword"},
                    "UserName": {"type": "keyword"},
                    "VSys": {"type": "keyword"},
                    "slot": {"type": "keyword"},
                    "results": {"type": "integer"}
                    
                    
                    

                    
                    

                    
                    
                }
            }
        }

        # Create the index with the specified settings and mappings
        es_client.indices.create(index=index_name, body=index_settings)

    # Assuming your DataFrame is named 'DF' and contains the 'log_id', 'results', '@timestamp', and 'attack' columns
    # Replace 'DF' with your actual DataFrame variable
    def doc_generator(df):
        for index, row in df.iterrows():
            yield {
                "_index": index_name,
                "_id": row["log_id"],
                "_source": {
                    "log_id": row["log_id"],
                    "@timestamp": row["@timestamp"],
                    "@version": row["@version"],
                    "Action": row["Action"],
                    "Application": row["Application"],
                    "Attack": row["Attack"],
                    "BeginTime": row["BeginTime"],
                    "Catagory": row["Category"],
                    "CloseReason": row["CloseReason"],
                    "Cpu": row["Cpu"],
                    "Destination-address": row["Destination-address"],
                    "Destination-port": row["Destination-port"],
                    "Destination-vpn-id": row["Destination-vpn-id"],
                    "Destination-zone": row["Destination-zone"],
                    "DstLocation": row["DstLocation"],
                    "EndTime": row["EndTime"],
                    "HostName": row["HostName"],
                    "IP-address": row["IP-address"],
                    "IPVer": row["IPVer"],
                    "MaxSpeed": row["MaxSpeed"],
                    "ModuleBrief": row["ModuleBrief"],
                    "ModuleName": row["ModuleName"],
                    "Os": row["Os"],
                    "Policy": row["Policy"],
                    "Policy-name": row["Policy-name"],
                    "Priority": row["Priority"],
                    "Profile": row["Profile"],
                    "Protocol-Name": row["Protocol-Name"],
                    "Protocol-Number": row["Protocol-Number"],
                    "RcvBytes": row["RcvBytes"],
                    "RcvPkts": row["RcvPkts"],
                    "RecieveInterface": row["RecieveInterface"],
                    "Role": row["Role"],
                    "SendBytes": row["SendBytes"],
                    "SendPkts": row["SendPkts"],
                    "Severity": row["Severity"],
                    "SignId": row["SignId"],
                    "SignName": row["SignName"],
                    "Source-address": row["Source-address"],
                    "Source-nat-address": row["Source-nat-address"],
                    "Source-nat-port": row["Source-nat-port"],
                    "Source-port": row["Source-port"],
                    "Source-vpn-id": row["Source-vpn-id"],
                    "Source-zone": row["Source-zone"],
                    "SrcLocation": row["SrcLocation"],
                    "SyslogId": row["SyslogId"],
                    "Target": row["Target"],
                    "Time": row["Time"],
                    "TotalPackets": row["TotalPackets"],
                    "UserName": row["UserName"],
                    "VSys": row["VSys"],
                    "slot": row["slot"],
                    "results": int(row["results"][0]) if isinstance(row["results"], list) else int(row["results"])


                    
                }
            }

    # Index the DataFrame into the existing Elasticsearch index
    helpers.bulk(es_client, doc_generator(DF2[["log_id", "@timestamp", "@version", "Action", "Application",
                                                "Attack", "BeginTime", "Category", "CloseReason", "Cpu", "Destination-address"
                                                , "Destination-port", "Destination-vpn-id", "Destination-zone", "DstLocation"
                                                , "EndTime", "HostName", "IP-address", "IPVer", "MaxSpeed", "ModuleBrief"
                                                , "ModuleName", "Os", "Policy", "Policy-name", "Priority", "Profile"
                                                , "Protocol-Name", "Protocol-Number", "RcvBytes", "RcvPkts"
                                                , "RecieveInterface", "Role", "SendBytes", "SendPkts", "Severity"
                                                , "SignId", "SignName", "Source-address", "Source-nat-address"
                                                , "Source-nat-port", "Source-port", "Source-vpn-id", "Source-zone"
                                                , "SrcLocation", "SyslogId", "Target", "Time", "TotalPackets"
                                                , "UserName", "VSys", "slot", "results"]]))


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
# ELASTICSEARCH_URL = "https://192.168.7.2:9200"
ELASTICSEARCH_URL = "https://192.168.7.100:9200"
ES_USERNAME = "elastic"
ES_PASSWORD = "ncsael@123"
INDEX_NAME = "siem-*"

# orignal dataframe
DF=pd.DataFrame()



create_db()#1
try:
    df_logs=add_new_time_values().copy()#2
except Exception as e:
    print(f"Failed to fetch logs: {e}")
    # Remove the last recorded end time from the log file
    with open("time_log.txt", 'r') as file:
        lines = file.readlines()
        lines = lines[:-1]

df_logs=filter_required_cols(df_logs).copy()#3
df_logs = df_logs.applymap(clean_value_special_symbols)#4
df_logs['Destination-address'] = df_logs['Destination-address'].apply(transform_ip)
df_logs['Source-address'] = df_logs['Source-address'].apply(transform_ip)
df_logs = transforming_columns(df_logs).copy()#6
replace_values_and_convert_to_numeric1(df_logs)#6
df_logs=find_processed_time(df_logs).copy()#8
df_logs=dig_timestamps(df_logs).copy()#9
# append_db(df_logs)#10

#finding time to process below function
import time
start_time = time.time()
dbscan(df_logs)#11
print("--- %s seconds ---" % (time.time() - start_time))

# Sending data to elastic search
start_time = time.time()
try:
    send2Elastic()
except Exception as e:
    # Remove the last recorded end time from the log file
    with open("time_log.txt", 'r') as file:
        lines = file.readlines()
        lines = lines[:-1]

    print(f"Failed to send data to Elasticsearch: {e}")
print("--- %s seconds ---" % (time.time() - start_time))









