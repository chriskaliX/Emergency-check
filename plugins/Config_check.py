from plugins.common.common import printf, align
import os,re

class Config_check:
    def __init__(self):
        self.suspicious_config = []
        self.name = u'Config File Check'
        self.ip_regex = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.ip_internal = '(127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(localhost)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3})|(100\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})'
        self.ip_common = '(8.8.8.8)|(114.114.114.114)'
    def ip_valid(self,line):
        return re.findall(self.ip_regex,line)

    def dns_check(self):
        try:
            ini = len(self.suspicious_config)
            if os.path.exists('/etc/resolv.conf'):
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        ips = self.ip_valid(line)
                        if ips:
                            for i in ips:
                                if re.match(self.ip_internal,i):
                                    continue
                                if re.match(self.ip_common,i):
                                    continue
                                self.suspicious_config.append(["/etc/resolv.conf", line])
            end = len(self.suspicious_config)
            return True if end == ini else False
        except:
            return True

    def iptables_check(self):
        try:
            #centos
            ini = len(self.suspicious_config)
            if os.path.exists("/etc/sysconfig/iptables"):
                with open("/etc/sysconfig/iptables") as f:
                    for line in f:
                        if len(line)<5:continue
                        if line[0] == "#":continue
                        if "ACCEPT" in line:
                            self.suspicious_config.append(["/etc/sysconfig/iptables"],line)
            end = len(self.suspicious_config)
            
            ##firewalld ufw (ubuntu or centos)
            return True if end == ini else False
        except:
            return True
    
    def host_check(self):
        if not os.path.exists("/etc/hosts"):
            return True
        else:
            ini = len(self.suspicious_config)
            with open("/etc/hosts") as f:
                for line in f:
                    if self.ip_valid(line):
                        for i in self.ip_valid(line):
                            if (re.match(self.ip_internal,i)):continue
                            else:self.suspicious_config.append(["/etc/hosts",i])
            end = len(self.suspicious_config)
            return True if end == ini else False
    
    def run(self):
        print(u'\n\033[1;33m%s\033[0m' % self.name)
        print(u'  %s%s' % (align("[1]DNS check"),printf(self.dns_check())))
        print(u'  %s%s' % (align("[2]iptables check"),printf(self.iptables_check())))
        print(u'  %s%s' % (align("[3]host check"),printf(self.host_check())))
        for detail in self.suspicious_config:
            print(u'    [*]File:%s[*]Detail:%s' %(align(detail[0]), detail[1]))
