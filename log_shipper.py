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
        self.redis = Redis(host,port)

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
    ls = LogShipper()
    ls.ship({'log_type':'ossec,hello'})
