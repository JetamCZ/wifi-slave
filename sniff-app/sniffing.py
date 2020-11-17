import os
import subprocess
import time
import atexit
from io import StringIO
import pandas as pd
import requests
import json
import argparse
LOG_FILE = 'airodump-log'
FNULL = open(os.devnull, 'w')

REMOVE_CSV_FILES_COMMAND = 'sudo rm -rf *.csv'
WAITING_DELAY = 15
UPDATE_INTERVAL = 30
MAXIMUM_AGE = 5 * 60
SERVER_UNREACHABLE_DELAY = 10


def getserial():
  # Extract serial from cpuinfo file
  cpuserial = "0000000000000000"
  try:
    f = open('/proc/cpuinfo','r')
    for line in f:
      if line[0:6]=='Serial':
        cpuserial = line[10:26]
    f.close()
  except:
    cpuserial = "ERROR000000000"
 
  return cpuserial

def start_wifi_monitoring():
    print("Starting background Wifi monitoring ...")
    os.system('sudo rm -rf *.csv')

    airodump_command = "sudo airodump-ng --output-format csv --write {} {}".format(LOG_FILE, args.wifi_interface)
    subprocess.Popen(airodump_command.split(" "), shell=False, stdout=FNULL, stderr=subprocess.STDOUT)


def exit_handler():
    print("Exiting...stopping scan..")

    #kill subprocess
    print("Stopping background Wifi monitoring ...")
    os.system('sudo killall airodump-ng')

def read_df():
    read_df = False
    while not read_df:
        try:
            csv_content = open(LOG_FILE + '-01.csv').read().strip()
            df = pd.read_csv(StringIO(csv_content), engine='c', error_bad_lines=False)
            read_df = True
        except:
            time.sleep(0.5)
    return df

def get_relevant_stations(df):
    df_stations = df.copy()
    df_stations = df_stations.rename(index=str, columns=dict(zip(df_stations.columns, [str(c).strip() for c in df_stations.columns])))
    df_stations = df_stations[["Station MAC", "Last time seen", "BSSID", "Power"]]
    time_pattern = ' %Y-%m-%d %H:%M:%S'

    try:
        df_stations["Last time seen"] = df_stations["Last time seen"].apply(lambda x: int(time.mktime(time.strptime(x, time_pattern))))
    except:
        raise Exception("Can't parse " + df_stations.to_string())

    df_stations["Time delta"] = (time.time() - df_stations["Last time seen"])
    df_stations = df_stations[df_stations["Time delta"] < MAXIMUM_AGE]
    df_stations = df_stations[df_stations["Power"].astype(int) < 0]

    return df_stations[["Station MAC", "Power", "Last time seen", "Time delta"]]

def get_stations(df):
    station_index = df.loc[df["BSSID"] == "Station MAC"].index[0]
    df_stations = df.loc[station_index:, :]

    new_header = df_stations.loc[station_index]
    df_stations = df_stations.loc[station_index + 1:]
    df_stations = df_stations.rename(columns=new_header)
    return get_relevant_stations(df_stations)

def send_measurements_to_server(df):
    devices = []

    for _, row in df.iterrows():
        devices.append({
            'mac': row["Station MAC"], 
            'rssi': int(row["Power"]), 
            'name': "", 
            'lastSaw': str(row["Last time seen"])
            })

    try:
        new_data = {
            'devices': devices,
            'device_key': getserial()
        }

        data = json.dumps(new_data)
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

        print("data", data)

        devices = []
        requests.post(url= "https://wifilocation.herokuapp.com/beacon", data = data, headers = headers)
    except Exception as e: 
        print(e)

def main():
    parser = argparse.ArgumentParser(description='Monitor nearby Wifi devices that are connected to the same network')
    parser.add_argument('-w', '--wifi-interface', required=True, help='Name of the Wifi network interface e.g. wlan0 or wlp3s0')

    args = parser.parse_args()

    print(args.wifi_interface)

    if os.getuid() != 0:
        print("you must run sudo!")
        return

    #START monitor mode
    os.system("ifconfig "+args.wifi_interface+" down")
    os.system("iwconfig "+args.wifi_interface+" mode monitor")
    os.system("ifconfig "+args.wifi_interface+" up")

    #register exhit handler
    atexit.register(exit_handler)

    #start airodump
    start_wifi_monitoring()

    #start reading
    while True:
        try:
            if os.path.isfile(LOG_FILE + '-01.csv'):
                df = read_df()
                df_stations = get_stations(df)

                if len(df_stations) > 0:
                    send_measurements_to_server(df_stations)
                else:
                    print("No nearby connected Wifi devices found")

            else:
                print("NO FILE")
        except Exception as e:
            print(e)

        time.sleep(2)


if __name__ == '__main__':
    main()