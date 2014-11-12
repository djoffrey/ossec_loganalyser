#coding=utf8
"""
parse ossec alert.log
"""
import re

class LogParser(object):
    def __init__(self,log_file=''):
        """
        do the pattern initialization
        """
        pat1_raw = r'\*\*\sAlert\s(?P<log_timestamp>[\d]{,10}\.[\d]{,6}):\s{1,3}.*-\s(?P<log_type>[^\n]+)\n(?P<log_time>[\d]{4}\s[\w]{,4}\s[\d]{1,2}\s\d\d:\d\d:\d\d)\s(?P<rhost>[^\)]*\))\s(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\-\>(?P<rule_path>[^\n]*)\nRule:\s(?P<rule_number>[\d]+)\s\(level (?P<severity>\d)\)\s\-\>\s\'(?P<log_message>[^\']+)\'\n(?P<remaining_message>.*)'
        pat2_raw = r'\*\*\sAlert\s(?P<log_timestamp>[\d]{,10}\.[\d]{,6}):\s{1,3}.*-\s(?P<log_type>[^\n]+)\n(?P<log_time>[\d]{4}\s[\w]{,4}\s[\d]{1,2}\s\d\d:\d\d:\d\d)\s(?P<rhost>[^\)]*\))\-\>(?P<rule_path>[^\n]*)\nRule:\s(?P<rule_number>[\d]+)\s\(level (?P<severity>\d)\)\s\-\>\s\'(?P<log_message>[^\']+)\'\n(?P<remaining_message>.*)'
        self.pat1 = re.compile(pat1_raw,re.S|re.M|re.I)
        self.pat2 = re.compile(pat2_raw,re.S|re.M|re.I)
        self.f = open(log_file,'r+')

    def get_one_log(self,f=None):
        if f == None:
            f = self.f
        new_line = f.readline()
        log_text = new_line
        while new_line != '\n':
            if new_line == '' or new_line == ' ':
                # EOF
                break
            new_line = f.readline()
            log_text = log_text + new_line
        return log_text

    def parse_one_log(self,log_text=''):
        """
        will try twice
        """
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
