
# 🛡️ ZooKeeper Insecure API Checker

A Python tool to detect insecure Apache ZooKeeper instances by testing for unauthenticated access, command execution, node enumeration, and optional write access.



## 📌 Features

- Connects to a ZooKeeper instance to check for open access.
- Executes the `ruok` command to verify responsiveness.
- Lists the children of the root node `/`.
- Retrieves Access Control Lists (ACLs) from the root.
- Optionally tests if write access is allowed (creates and deletes a test node).
- Generates a proof-of-vulnerability output file.




## 📦 Installation

 Clone the repository:


```bash
  git clone https://github.com/XK3NF4/ZooKeeper-Security-Check-API.git
  cd ZooKeeper-Security-Check-API

```
Install dependencies:
```bash
  pip3 install -r requirements.txt
```



    
## 🧪Usage/Examples

1 - Create a file (e.g., targets.txt) with the ZooKeeper host and port:
```bash
192.168.1.100:2181
```
2 - Run the tool:
```bash
python3 ZooKeeper_Security_Check.py -f targets.txt --proof output.txt
```
- Use the --no-write flag to disable the write test (recommended for passive checks):
```bash
python3 ZooKeeper_Security_Check.py -f targets.txt --proof output.txt --no-write
```


## 📝 Example Output

```
Zookeeper API Security Check

Connected to: 192.168.1.100

Results of ruok command: imok

Client ID: 123456789

Root directory contents: zookeeper config app

ACLS: ...

Created directory /XK3NF4 and node /XK3NF4/node

Deleted /XK3NF4 and all its contents

```



## ⚠️ Disclaimer
This tool is for educational and authorized testing purposes only. Use it responsibly and only on systems you have permission to assess.
