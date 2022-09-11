import argparse
import psutil
import frida
import json
import sys
from datetime import datetime

SCRIPT_PATH = "avm_script.js"

# Packet id blacklist
BLACKLIST = []

#IN_PACKET = 0
#OUT_PACKET = 1

class PacketDumper:
    def __init__(self, pid : int, out_file_name = None, json_only = False):
        if out_file_name:
            self.output_file = open(out_file_name, "r")
        else:
            self.output_file = None
        self.json_only = json_only
        self.pid = pid

    def __del__(self):
        if self.output_file:
            self.output_file.close()

    def write_output(self, packet_type, packet_id, name, payload, trace):
        output = ""
        current_t = datetime.now().isoformat()

        if self.json_only:
            output = json.dumps({ "type" : packet_type, "time" : current_t, "id": packet_id, "name" : name, "data" : payload, "stacktrace" : trace })
        else:
            json_content = json.dumps(payload, indent=4)
            if packet_type == 0:
                output = "Received packet {0: >5s} [{1: >6d}] [{2:s}]\n{3:s}\n".format(name, packet_id, current_t, json_content)
            else:
                output = "Sending packet  {0: >5s} [{1: >6d}] [{2:s}]\n{3:s}\n".format(name, packet_id, current_t, json_content)
                output += f"Stacktrace for [{packet_id}]\n"
                output += "\n".join(["{0:3d} - {1:s}".format(i, name) for i,name in enumerate(trace)])

        output += "\n"

        if self.output_file:
            self.output_file.write(output)

        print(output)

    def on_message(self, msg, data):
        if msg["type"] == "send":
            payload = msg["payload"]
            try:
                BLACKLIST.index(int(payload["id"]))
                return
            except:
                pass

            self.write_output(payload["type"], int(payload["id"]), payload["name"], payload["packet"], payload["stacktrace"])

        elif msg["type"] == "error":
            print(json.dumps(msg, indent=4))
        else:
            print(msg)

    def run(self):
        try:
            session = frida.attach(self.pid)
        except frida.ProcessNotRespondingError as e:
            print(e)
            print("Try launching the chromium process with --no-sandbox")
            sys.exit(-1)

        script = session.create_script(open(SCRIPT_PATH).read())

        script.on('message', self.on_message)

        script.load()

        input('[!] Press <Enter> to stop.')

        session.detach()

def find_flash_process():
    for proc in psutil.process_iter(["pid", "ppid", "cmdline"]):
        try:
            flash_lib = next(filter(lambda m: m.path.find("Flash.ocx") >= 0, proc.memory_maps()))
        except:
            flash_lib = None

        if flash_lib != None or (proc.info["cmdline"] and "--type=ppapi" in proc.info["cmdline"]):
            return proc.info.get("pid")
    return 0

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--log',  dest="log_file", nargs="?", const=(datetime.now().strftime("%Y-%m-%d_%H-%M-%S.log")), type=str, help="Output file")
    parser.add_argument('-j', '--json', dest="json", action="store_true", required=False, help="Json ouput.")
    parser.add_argument('-p', '--pid',  dest="pid", type=int, required=False, help="Process id")
    return parser.parse_args()

def main():
    args = parse_args()

    pid = args.pid or find_flash_process()

    if not pid:
        print("[!] No pid. Stopping.")
        return
    else:
        print(f"[+] Dumping on process {pid}.")

    dumper = PacketDumper(pid, args.log_file, args.json)
    dumper.run()

if __name__ == "__main__":
    main()
