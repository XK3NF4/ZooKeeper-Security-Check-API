# -*- coding: UTF-8 -*-
# ToolName   : ZooKeeper_Security_Check.py
# Author     : XK3NF4
# Github     : https://github.com/XK3NF4
# Contact    : https://t.me/XK3NF4
# Description: Anonymous access validator for ZooKeeper API
# Language   : Python3
# Env        : #!/usr/bin/env python3

import argparse
from kazoo.client import KazooClient

RED = '\033[31m'
GREEN = '\033[32m'
BLUE = '\033[34m'
RESET = '\033[0m'

def check_zookeeper_security(host, port, outputfile, write_permissions_allowed):
    try:
        zk = KazooClient(f'{host}:{port}')
        zk.start()
        command_output = {}
        ruok_response = None
        client_id = None
        acls = None
        root_children = None

        if zk.connected:
            with open(outputfile, 'w') as outfile:
                outfile.write('Zookeeper API Security Check\n\n')
                outfile.write(f'Connected to: {host}\n\n')
                command_output['status'] = zk.client_state

                try:
                    ruok_response = zk.command(cmd=b'ruok')
                except Exception:
                    pass

                if ruok_response and 'whitelist' not in ruok_response and 'ruok is not executed' not in ruok_response:
                    outfile.write(f'Results of ruok command: {ruok_response}\n\n')
                    command_output['ruok_cmd_results'] = ruok_response

                try:
                    client_id = zk.client_id[0]
                except Exception:
                    pass

                if client_id:
                    outfile.write(f'Client ID: {client_id}\n\n')
                    command_output['client_id'] = client_id

                try:
                    root_children = zk.get_children('/')
                except Exception:
                    pass

                if root_children:
                    outfile.write(f"Root directory contents: {' '.join(root_children)}\n\n")
                    command_output['current_directory'] = root_children

                try:
                    acls = zk.get_acls('/')
                except Exception:
                    pass

                if acls:
                    outfile.write(f'ACLS: {str(acls)}\n\n')
                    command_output['acls'] = acls

                if write_permissions_allowed:
                    directory_created = False
                    directory_deleted = False
                    try:
                        zk.ensure_path("/XK3NF4")
                        zk.create("/XK3NF4/node", b"vulnerable api")
                        outfile.write('Created directory /XK3NF4 and node /XK3NF4/node\n\n')
                        directory_created = True
                    except Exception:
                        pass

                    if directory_created:
                        try:
                            ch = zk.get_children('/')
                            outfile.write(f"New root directory contents: {' '.join(ch)}\n\n")

                            zk.delete("/XK3NF4", recursive=True)
                            outfile.write('Deleted /XK3NF4 and all its contents\n\n')
                            directory_deleted = True

                            if directory_deleted:
                                outfile.write('The /XK3NF4 directory has been cleaned up.\n\n')
                            else:
                                outfile.write(f'The /XK3NF4 directory could not be deleted, please manually remove the artifact from {host}.\n\n')
                        except Exception:
                            pass

                    try:
                        ch = zk.get_children('/')
                        if ch:
                            outfile.write(f"Root directory contents: {' '.join(ch)}\n")
                    except Exception:
                        pass

                zk.stop()
                return True

    except Exception as e:
        print(f"Error during Zookeeper check: {e}")
        return False


def parse_arguments():
    parser = argparse.ArgumentParser(description="Zookeeper security check utility.")
    parser.add_argument('-f', required=True, help='File containing host information')
    parser.add_argument('--proof', required=True, help='File to output security proof results')
    parser.add_argument('--no-write', action='store_false', help='Disable write permission checks')

    return parser.parse_args()

def danner():
    print(BLUE + """
███████╗ ██████╗  ██████╗ ██╗  ██╗███████╗███████╗██████╗ ███████╗██████╗     ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
╚══███╔╝██╔═══██╗██╔═══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ███╔╝ ██║   ██║██║   ██║█████╔╝ █████╗  █████╗  ██████╔╝█████╗  ██████╔╝    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝     ██║     ███████║█████╗  ██║     █████╔╝ 
 ███╔╝  ██║   ██║██║   ██║██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝      ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
███████╗╚██████╔╝╚██████╔╝██║  ██╗███████╗███████╗██║     ███████╗██║  ██║    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║       ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝        ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
                                                                                                                                                                by XK3NF4
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
          """ + RESET)

if __name__ == "__main__":
    args = parse_arguments()

    with open(args.f, 'r') as input_file:
        host_info = input_file.readlines()
    
    host_info = [line.strip() for line in host_info if line.strip()]
    
    if host_info:
        host, port = host_info[0].split(':')
        port = str(port)
        security_check_passed = check_zookeeper_security(host, port, args.proof, args.no_write)
        danner()    

        if security_check_passed:
            print(RED + '\t[+] Insecure Zookeeper instance detected. 💀' + RESET)
        else:
            print(GREEN + '\t[*] Zookeeper instance appears to be secured. 💚' + RESET)
    else:
        print("No host information found in the input file.")
