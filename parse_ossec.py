#coding=utf8
"""
parse ossec alert.log
"""
import re
from redis import Redis
import json
"""
{"remaining_message": "Src IP: 10.0.0.96\\n10.0.0.96 - - [10/Nov/2014:18:25:07 +0800] \\"GET /xhprof_html/index.php?run=5460925d3eb96&source=xhprof_foo HTTP/1.0\\" 200 1961 \\"-\\" \\"Wget/1.12 (linux-gnu)\\"\\n\\n",
"severity": "6",
"ip": "10.0.0.24",
 "log_timestamp": "1415615109.103674",
"rule_number": "31511",
"rule_path": "/var/log/nginx/access.log",
"log_message": "Blacklisted user agent (wget).",
 "log_time": "2014 Nov 10 18:25:09",
 "log_type": "web,appsec,attack",
"rhost": "(hosts.com)"}
"""

class LogParser(object):
    def __init__(self):
        """
        do the pattern initialization
        """
        pat1_raw = r'\*\*\sAlert\s(?P<log_timestamp>[\d]{,10}\.[\d]{,6}):\s{1,3}.*-\s(?P<log_type>[^\n]+)\n(?P<log_time>[\d]{4}\s[\w]{,4}\s[\d]{1,2}\s\d\d:\d\d:\d\d)\s(?P<rhost>[^\)]*\))\s(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\-\>(?P<rule_path>[^\n]*)\nRule:\s(?P<rule_number>[\d]+)\s\(level (?P<severity>\d)\)\s\-\>\s\'(?P<log_message>[^\']+)\'\n(?P<remaining_message>.*)'
        pat2_raw = r'\*\*\sAlert\s(?P<log_timestamp>[\d]{,10}\.[\d]{,6}):\s{1,3}.*-\s(?P<log_type>[^\n]+)\n(?P<log_time>[\d]{4}\s[\w]{,4}\s[\d]{1,2}\s\d\d:\d\d:\d\d)\s(?P<rhost>[^\)]*\))\-\>(?P<rule_path>[^\n]*)\nRule:\s(?P<rule_number>[\d]+)\s\(level (?P<severity>\d)\)\s\-\>\s\'(?P<log_message>[^\']+)\'\n(?P<remaining_message>.*)'
        self.pat1 = re.compile(pat1_raw,re.S|re.M|re.I)
        self.pat2 = re.compile(pat2_raw,re.S|re.M|re.I)
        self.rkey = 'ossec-alerts-log'
        try:
            self.redis = Redis(host='127.0.0.1', port=6379)
        except Exception,e:
            print('error at building redis connection!')

    def get_one_log(self):
        if self.redis == None:
            self.redis = Redis(host='127.0.0.1', port=6379)
        r = self.redis
        if r.llen(self.rkey) > 0:
            return json.loads(r.lpop(self.rkey))
        else:
            return None
        
    def parse_one_log(self,log_text=''):
        """
        will try twice
        """
        if log_text=='' or log_text==' ':
            return None
        match = re.search(self.pat1,log_text)
        if match == None:
            match = re.search(self.pat2,log_text)
            if match == None:
                #die for shame
                # print ?
                return None
            else:
                return match.groupdict()
        else:
            # print ?
            return match.groupdict()

if __name__ == '__main__':
    lp = LogParser()
    print(lp.get_one_log())
