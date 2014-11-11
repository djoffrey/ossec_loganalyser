"""
parse ossec alert.log
"""
import re

line1_pat = r'\*\*\sAlert\s(?P<log_timestamp>[\d]{,10}\.[\d]{,6}):\s-\s(?P<log_type>[^\n]+)\n'

log_time_pat = r'(?P<log_time>[\d]{4}\s[\w]{,4}\s[\d]{1,2}\s\d\d:\d\d:\d\d)'

rhost_pat = r'(?P<rhost>[^\)]*\))'

rhost_ip_pat = rhost_pat + r'\s(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'

line2_pat = log_time_pat + '\s' + rhost_pat + '\-\>(?P<rule_path>[^\n]*)'

line2_ip_pat = log_time_pat + '\s' + rhost_ip_pat + '\-\>(?P<rule_path>[^\n]*)'

line3_pat = '\nRule:\s(?P<rule_number>[\d]+)\s\(level (?P<severity>\d)\)\s\-\>\s\'(?P<log_message>[^\']+)\'\n(?P<remaining_message>.*)'

pat1_raw = r'\*\*\sAlert\s(?P<log_timestamp>[\d]{,10}\.[\d]{,6}):\s-\s(?P<log_type>[^\n]+)\n(?P<log_time>[\d]{4}\s[\w]{,4}\s[\d]{1,2}\s\d\d:\d\d:\d\d)\s(?P<rhost>[^\)]*\))\s(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\-\>(?P<rule_path>[^\n]*)\nRule:\s(?P<rule_number>[\d]+)\s\(level (?P<severity>\d)\)\s\-\>\s\'(?P<log_message>[^\']+)\'\n(?P<remaining_message>.*)'

pat2_raw = r'\*\*\sAlert\s(?P<log_timestamp>[\d]{,10}\.[\d]{,6}):\s-\s(?P<log_type>[^\n]+)\n(?P<log_time>[\d]{4}\s[\w]{,4}\s[\d]{1,2}\s\d\d:\d\d:\d\d)\s(?P<rhost>[^\)]*\))\-\>(?P<rule_path>[^\n]*)\nRule:\s(?P<rule_number>[\d]+)\s\(level (?P<severity>\d)\)\s\-\>\s\'(?P<log_message>[^\']+)\'\n(?P<remaining_message>.*)'


pat1 = re.compile(pat1_raw,re.S|re.M|re.M)
pat2 = re.compile(pat2_raw,re.S|re.M|re.M)

def get_one_log(fd):
    new_line = fd.readline()
    log_text = new_line
    while new_line != '\n':
        new_line = fd.readline()
        log_text = log_text + new_line
    return log_text

def parse_one_log(log_text):
    """
    will try twice
    """
    match = re.search(pat1)
p    if match == None:
        match = re.search(pat2)
        if match == None:
            #die for shame
            # print ?
            return None
        return match.groupdict()
    else:
        # print ?
        return None
