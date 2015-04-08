#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Send mail to target
"""
import sys
import smtplib
import time
import datetime
from email.mime.text import MIMEText

mailto_list_test=["test@xx.com"]
from_addr = ""

mail_server = ""
mail_user = "hids"
mail_pass = "pass"
mail_post_fix = "xx.com"

def SendMail(fromaddr=from_addr,mailto=mailto_list_test,content=""):
    msg = MIMEText(content,'html','utf-8')
    print("Constructing msg... {0}".format(datetime.datetime.fromtimestamp(time.time())))
    msg['Subject'] = "HIDS Alert "+str(datetime.datetime.now())
    msg['From'] = from_addr
    msg['To'] = ";".join(mailto)
    s = smtplib.SMTP_SSL()
    s.connect(mail_server)
    s.login(from_addr,mail_pass)
    print("connect ok.start sending..")
    s.sendmail(fromaddr,mailto,msg.as_string())
    s.close()
    print("success!")

