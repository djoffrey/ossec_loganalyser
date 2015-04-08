#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ship log to email group
"""
from __future__ import print_function
from parse_ossec import LogParser
import SendMail as SM
import datetime
import time

# get email corresponding person email
def get_group_hostname(fName='/home/huangyucheng/ossec_loganalyser/group_hostnames.csv'):
    res = {}
    with open(fName) as f:
        for l in f.readlines():
            hostname,group = l.split(',')
            res[hostname.strip()] = int(group.strip())
    return res

def register_group_email(fName='/home/huangyucheng/ossec_loganalyser/email_concern_list.csv'):
    res = {}
    with open(fName) as f:
        for l in f.readlines():
            name,group,level = l.split(',')
            res[name] = {'name':name.strip()+'@huobi.com',
                         'group': [elem for elem in group.split('|')],
                         'level': int(level)}
    return res

group_hostname = get_group_hostname()
group_email = register_group_email()

def make_content(log):
    content = ""
    for i in ['reporting_host','reporting_source','severity','signature','rule_number','real_message','syslog_timestamp']:
        try:
            content = '{0}<tr><td style="margin-left:20px"><strong>{1}</strong></td>\r\n<td><strong>{2}</strong></td></tr>\r\n'.format(content,i,log[i])
        except Exception,e:
            print('error {0}'.format(e))
            continue
    with open('/home/huangyucheng/ossec_loganalyser/mail_temp.html','r+') as f:
        body = f.read()
    body = body.format(content)
    return body

def process_one_log(log):
    host = log['reporting_host']
    level = int(log['severity'])
    try:
        group = group_hostname[host]
    except Exception,e:
        print('the host is {0}'.format(e))
        return 0
    mailto_list = []
    for _,v in group_email.items():
        if '*' in v['group'] and v['level'] <= level:
            mailto_list.append(v['name'])
        elif str(group) in v['group'] and v['level'] <= level:
            mailto_list.append(v['name'])
    # early break here
    if len(mailto_list) == 0:
        print("Level is {0} ,No mail has been sent at all!".format(level))
        return 0
    try:
        print("Sending mail to {0},the log host`s group is {1}".format(mailto_list,group))
        SM.SendMail(content=make_content(log),mailto=mailto_list)
        time.sleep(0.3)
    except Exception,e:
        print('error at:{0}'.format(e))
    return 1

def process_logs():
    #get mailto list
    lp = LogParser()
    pending_list = []
    while 1:
        log = lp.get_one_log()
        if log == None:
            break
        else:
            pending_list.append(log)
    print("there are {0} logs. time:{1}".format(len(pending_list),datetime.datetime.now()))
    total_send = 0
    for log in pending_list:
        total_send += process_one_log(log)
    return total_send

def main():
    process_logs()

if __name__ == '__main__':
    # print(get_group_hostname())
    # SendMail(content=make_content('<a href="http://www.huobi.com">hello,hids<a>'))
    main()
