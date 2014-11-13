#coding=utf8
"""
ship ossec parse result to redis server
"""

from redis import Redis
import json

# host : localhost
# port : 6379
class LogShipper(object):
    """

    """
    def __init__(self,rhost='127.0.0.1',port=6379):
        self.redis = Redis(rhost,port)

    def ship(self,d):
        """
        use the log dict ['log_type']
        and append self type to redis queue named 'log_types'
        """
        try:
            ret = self.redis.lpush(d['log_type'],json.dumps(d))
            ret = self.redis.lpush('log_types',d['log_type'])
        except Exception,e:
            print(e)
            return -1
        return ret


if __name__=='__main__':
    from parse_ossec import LogParse
    lp = LogParser(log_file='/var/ossec/logs/alerts/alerts.log')
    ls = LogShipper(rhost='127.0.0.1',port=6379)

    alert_text = lp.get_one_log()
    while 1:
        if alert_text == '' or alert_text == ' ':
            # EOF
            break
        else:
            alert_dict = lp.parse_one_log(alert_text)
            alert_text = lp.get_one_log()
            if alert_dict == None:
                continue
            ls.ship(alert_dict)

    print("parse and ship done.")
