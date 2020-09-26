import sys
from time import sleep
import splunklib.results as results

import splunklib.client as client
import config

conf = config.auth
user = conf['username']
passw = conf['password']
port = conf['port']
host = conf['host']

service = client.connect(host=host, port=port, username=user, password=passw)

# obtained this template from Splunk's dev documentation
# <source>: https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython/howtorunsearchespython
def get_audit_logs():
    kwargs_export = {"earliest_time": "-7d",
                     "latest_time": "now",
                     "search_mode": "normal"}
    searchquery_export = "search index=_audit"

    exportsearch_results = service.jobs.export(searchquery_export, **kwargs_export)

    # Get the results and display them using the ResultsReader
    reader = results.ResultsReader(exportsearch_results)
    for result in reader:
        if isinstance(result, dict):
            yield result['_raw']
        elif isinstance(result, results.Message):
            # Diagnostic messages may be returned in the results
            # Not sure what to do with these messages... look like error messages
            continue

def crawl_login_attempts():
    for log in get_audit_logs():
        # I am sorry for the weird parsing... this could definitely be improved with find() calls
        log = log.replace("Audit:", "").replace("[","").replace("]","").split(",")
        action = log[2].replace(" ", "")
        if action == "action=loginattempt":
            print log
            timestamp, user = log[0], log[1].replace(" ", "")
            # logs are in a weird format, so need to do some cleaning to get the status of login
            status_idx = log[3].find("info=")
            ip_idx = log[3].find("clientip=")
            status, client_ip = "", ""
            if status_idx != -1:
                status = log[3][status_idx:].split(" ")[0]
            if ip_idx != -1:
                client_ip = log[3][ip_idx:].split(" ")[0]
            else:
                # clientip can also be called src in some logs
                if len(log) > 4:
	            ip_idx = log[4].find("src=")
        	    if ip_idx != -1:
               	        client_ip = log[4][ip_idx:].split(" ")[0]
            yield timestamp + " " + user + " " + status.replace("info=", "status=") + " " + client_ip.replace("clientip=", "src=")

def main():
    for login_attempt in crawl_login_attempts():
        print login_attempt

main()

