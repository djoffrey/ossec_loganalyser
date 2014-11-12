#encoding=utf8
"""
main worker
"""


from parse_ossec import LogParser
from log_shipper import LogShipper


if __name__=='__main__':
    lp = LogParser(log_file='/var/ossec/logs/alerts/alerts.log')
    ls = LogShipper(rhost='127.0.0.1',port=6379)

    alert_text = lp.get_one_log()
    while 1:
        if alert_text == '':
            # EOF
            break
        else:
            alert_dict = lp.parse_one_log(alert_text)
            if alert_dict == None:
                continue
            ls.ship(alert_dict)
            alert_text = lp.get_one_log()

    print("parse and ship done.")
