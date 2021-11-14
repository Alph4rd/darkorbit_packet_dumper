import argparse
import psutil
import frida
import json
import sys
import os
import re
from datetime import datetime

blacklist = []
output_file = None
output_json = False
#IN_PACKET = 0
#OUT_PACKET = 1

def find_flash_process():
    for proc in psutil.process_iter(["pid", "ppid", "cmdline"]):
        if proc.info["cmdline"] and "--type=ppapi" in proc.info["cmdline"]:
            return(proc.info["pid"])
    return None

def write_output(packet_type, packet_id, name, payload):
    global output_json, output_file

    output = ""
    current_t = datetime.now().isoformat()

    if output_json:
        output = json.dumps({ "type" : packet_type, "time" : current_t, "id": packet_id, "name" : name, "data" : payload })
    else:
        json_content = json.dumps(payload, indent=4)
        if packet_type == 0:
            output = "Received packet {0: >5s} [{1: >6d}] [{2:s}]\n{3:s}".format(name, packet_id, current_t, json_content)
        else:
            output = "Sending packet  {0: >5s} [{1: >6d}] [{2:s}]\n{3:s}".format(name, packet_id, current_t, json_content)

    if output_file:
        output_file.write(output+ "\n")

    print(output)

def on_message(msg, data):
    if msg["type"] == "send":
        payload = msg["payload"]
        try:
            blacklist.index(int(payload["id"]))
            return
        except:
            pass
        write_output(payload["type"], int(payload["id"]), payload["name"], payload["packet"])

    elif msg["type"] == "error":
        print(json.dumps(msg, indent=4))
    else:
        print(msg)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--log', dest="log_file", nargs="?", const=(datetime.now().strftime("%Y-%m-%d_%H-%M-%S.log")), type=str, help="Output file")
    parser.add_argument('-j', '--json', dest="json", action="store_true", required=False, help="Json ouput.")

    return parser.parse_args()

def main():
    global output_file, output_json
    args = parse_args()

    if args.log_file != None:
        print(args.log_file)
        output_file = open(args.log_file, "w")
    output_json = args.json == True

    pid = find_flash_process()

    if not pid:
        print("[!] Failed to find process.")
        return

    print(f"[+] Found process{pid}.")

    try:
        session = frida.attach(pid)
    except frida.ProcessNotRespondingError as e:
        print(e)
        print("Try launching the chromium process with --no-sandbox")
        sys.exit(-1)

    script = session.create_script(open("avm_script.js").read())

    script.on('message', on_message)

    script.load()

    input('[!] Press <Enter> to stop.')

    session.detach()

if __name__ == "__main__":
    main()
