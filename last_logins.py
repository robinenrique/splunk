import sys
from time import sleep
import splunklib.results as results

import splunklib.client as client
import config

# config.py should be populated with remote client or localhost, port 8089 and valid credentials
def get_config():
    conf = config.auth
    user = conf['username']
    passw = conf['password']
    port = conf['port']
    host = conf['host']
    return [host, port, user, passw]

# start connection
host, port, user, passw = get_config()
service = client.connect(host=host, port=port, username=user, password=passw)

# used dev documentation found on: https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython
def get_audit_logs():
    # setup search interval
    kwargs_export = {"earliest_time": "-7d", # 1 week from now
                     "latest_time": "now",
                     "search_mode": "normal"}

    # search in the _audit index
    query = "search index=_audit"
    exportsearch_results = service.jobs.export(query, **kwargs_export)

    # display results
    reader = results.ResultsReader(exportsearch_results)
    for result in reader:
        if isinstance(result, dict):
            yield result['_raw']

# crawls the _raw values in logs
def crawl_login_attempts():
    for log in get_audit_logs():
        # getting rid of weird chars, this could be improved with a regex or better string patterns
        log = log.replace("Audit:", "").replace("[","").replace("]","").split(",")
        action = log[2].replace(" ", "")
        
        # login - check if successful or failed
        if action == "action=loginattempt":
            # some more cleaning that can be improved
            timestamp, user = log[0], log[1].replace(" ", "")
            status_idx = log[3].find("info=")
            ip_idx = log[3].find("clientip=")

            status, client_ip = "", ""
            if status_idx != -1:
                status = log[3][status_idx:].split(" ")[0]
            if ip_idx != -1:
                client_ip = log[3][ip_idx:].split(" ")[0]
            else:
                # started running into some edge cases e.g.: clientip can also be called src in some logs
                # this is not covering 100% of the logs atm
                if len(log) > 4:
	            ip_idx = log[4].find("src=")
        	    if ip_idx != -1:
               	        client_ip = log[4][ip_idx:].split(" ")[0]
            # yield msg
            yield timestamp + " " + user + " " + status.replace("info=", "status=") + " " + client_ip.replace("clientip=", "src=")

def main():
    for login_attempt in crawl_login_attempts():
        print login_attempt

main()

