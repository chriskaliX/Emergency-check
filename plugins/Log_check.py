from plugins.common.common import printf, strings, align
from package.lastlog import lastlog
import os,re,datetime
from package.utmp import read

#How to warm this
class Log_check:
    def __init__(self):
        self.suspicious_log = []
        self.name = u'Log File Check'
        self.ip_regex = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.ip_internal = '^(127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(localhost)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3})$'

    #Get the lastest login_ip,all should be suspicious,and have to look at it
    #WHEN MORE THAN 1 IP,IT WILL ALERT,U HAVE TO CHECK IT
    def wtmp_check(self):
        login_list = {}
        if os.path.exists("/var/log/wtmp"):
            ini = len(self.suspicious_log)
            with open('/var/log/wtmp', 'rb') as fd:
                buf = fd.read()
                for entry in read(buf):
                    if re.match(self.ip_regex,entry.host):
                        #I don't check the internal ip,But u can change this
                        if re.match(self.ip_internal, entry.host):continue
                        identity = (entry.host,entry.user)
                        if (identity in login_list):
                            if (entry.sec) > (login_list[identity]):
                                login_list[identity] = entry.sec
                        else:
                            login_list[identity] = entry.sec
            if len(login_list) < 2:
                return True
            for key,value in login_list.items():
                value = datetime.datetime.utcfromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S")
                self.suspicious_log.append(["/var/log/wtmp","User,addr:%sTime:%s"%(align(",".join(key),width=30),value)])
            end = len(self.suspicious_log)
            return True if ini == end else False
        else:
            return True
    
    #When more than one online, warn
    def utmp_check(self):
        if os.path.exists("/var/run/utmp"):
            login_list = {}
            ini = len(self.suspicious_log)
            with open("/var/run/utmp","rb") as fd:
                buf = fd.read()
                for entry in read(buf):
                    if re.match(self.ip_regex, entry.host):
                        identity = (entry.host, entry.user)
                        if (identity in login_list):
                            if (entry.sec) > (login_list[identity]):
                                login_list[identity] = entry.sec
                        else:
                            login_list[identity] = entry.sec
        #When more than one online,it will warn
            if len(login_list) < 2:
                return True
            for key, value in login_list.items():
                    value = datetime.datetime.utcfromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S")
                    self.suspicious_log.append(["/var/log/utmp", "%s" % align(",".join(key), width=30)])
            end = len(self.suspicious_log)
            return True if ini == end else False
        else:
            return True

    def lastlog_check(self):
        #get the dict of username and uid
        def usermap():
            return_dict = {}
            with open("/etc/passwd") as fd:
                for line in fd:
                    the_list = line.split(":")
                    return_dict[the_list[2]] = the_list[0]
            return return_dict
        ini = len(self.suspicious_log)

        usermap = usermap()
        if not os.path.exists("/var/log/lastlog"):
            return True
        for uid in usermap:
            result = lastlog("/var/log/lastlog",uid)
            if result:
                if re.match(self.ip_internal,result[2]):continue
                self.suspicious_log.append(["/var/log/lastlog","User:%s IP:%s Time:%s"%(usermap[uid],result[2],result[0])])
        end = len(self.suspicious_log)
        return True if ini == end else False

    def authlog_check(self):
        sub_list = []
        ini = len(self.suspicious_log)
        if os.path.exists("/var/log/"):
            dir_list = os.listdir("/var/log/")
            for sub_file in dir_list:
                if re.match(r"^(auth.log).*?(\d+)$'", sub_file):
                    with open(sub_file,"r") as fi:
                        for line in fi:
                            if "Accept" in line:
                                if re.match(self.ip_internal,line):continue
                                sub_list.append(re.findall(self.ip_regex,line)[0])
        sub_list = list(set(sub_list))
        if len(sub_list)>1:
            for subip in sub_list:
                self.suspicious_log.append(["/var/log/authlog","IP:%s"%subip])
        end = len(self.suspicious_log)
        return True if ini == end else False

    def run(self):
        print(u'\n\033[1;33m%s\033[0m' % self.name)
        print(u'  %s%s' % (align("[1]wtmp check"),printf(self.wtmp_check())))
        print(u'  %s%s' % (align("[2]utmp check"),printf(self.utmp_check())))
        print(u'  %s%s' % (align("[3]lastlog check"),printf(self.lastlog_check())))
        print(u'  %s%s' % (align("[4]authlog check"), printf(self.authlog_check())))
        for detail in self.suspicious_log:
            print(u'    [*]File:%s[*]Detail:%s' % (align(detail[0],width=30), detail[1]))
