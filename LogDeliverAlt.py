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
from redis import Redis
import sys

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
            content = '{0}<tr><td style="margin-left:20px"><strong>{1}</strong></td>\r\n<td><strong>{2}</strong></td></tr>\r\n'.format(content,i.replace('\n','<br>'),log[i].replace('\n','<br>'))
        except Exception,e:
            print('error {0}'.format(e))
            continue
    content = '<table width="95%" border="10" style="margin-left:auto;">{0}<tbody></tbody></table><br>'.format(content)
    return content

def render_body(content_list):
    contents = ""
    for c in content_list:
        contents = '{0}<br>{1}'.format(contents,c)
    body = ""
    with open('/home/huangyucheng/ossec_loganalyser/mail_temp_alt.html','r+') as f:
        body = f.read()
    body = body.format(contents)
    return body
        
def process_one_log(log):
    host = log['reporting_host']
    level = int(log['severity'])
    try:
        group = group_hostname[host]
    except Exception,e:
        #print('the host is {0}'.format(e))
        return 0
    if level < 7:
        #print("level is {0} ,No mail should be sent!".format(level))
        return 0
    content = make_content(log)
    # (group,level,table)
    group_level = '{0}_{1}'.format(group,level)
    r = Redis()
    r.sadd('group_level_set',group_level)
    print('saving {0}'.format(group_level))
    r.lpush(group_level,content)
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
    #print("there are {0} logs. time:{1}".format(len(pending_list),datetime.datetime.now()))
    total_send = 0
    for log in pending_list:
        total_send += process_one_log(log)
    return total_send

def main():
    process_logs()

def get_sendlist_by_group_level(group,level):
    mailto_list = []
    for _,v in group_email.items():
        if '*' in v['group'] and v['level'] <= level:
            mailto_list.append(v['name'])
        elif str(group) in v['group'] and v['level'] <= level:
            mailto_list.append(v['name'])
        else:
            continue
    return mailto_list 

def send_mail_all():
    """
    God Bless me that can me read this code after a month!
    """
    r = Redis()
    group_levels = []
    while 1:
        group_level = r.spop('group_level_set')
        if group_level == None:
            break
        group_levels.append(group_level)
    print('{0} are to be processed.'.format(group_levels))
    for g_l in group_levels:
        # we do send mail here by group/level pair
        group,level = g_l.split('_')
        mailto_list = get_sendlist_by_group_level(int(group),int(level))
        # if nobody wants this log
        if len(mailto_list) == 0:
            continue
        print('group:{0} level:{1} mailto:{2} is to be sent!'.format(group,level,mailto_list))
        content_list = []
        while 1:
            content = r.lpop(g_l)
            if content == None:
                break
            content_list.append(content)
        body = render_body(content_list)
        SM.SendMail(content=body,mailto=mailto_list)


if __name__ == '__main__':
    # print(get_group_hostname())
    # SendMail(content=make_content('<a href="http://www.huobi.com">hello,hids<a>'))
    import sys
    if len(sys.argv) == 1:
        main()
    elif sys.argv[1] == 'sendmail':
        send_mail_all()
    else:
        raise Exception('Error!')
