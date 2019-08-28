from plugins.common.common import printf, strings, align
from plugins.common.Analysis import analysis,check_all
import os,re,time
class Proc_check:
    def __init__(self,cpu=70,mem=70):
        self.cpu, self.mem = cpu,mem
        self.suspicious_proc = []
        self.name = "Proc Security Check"
    
    def exe_check(self):
        try:
            ini = len(self.suspicious_proc)
            if not os.path.exists("/proc/"):
                return True
            for files in os.listdir("/proc/"):
                if files.isdigit():
                    filepath = os.path.join("%s%s%s" % ("/proc/",files,"/exe/"))
                    if (not os.path.islink(filepath)) or (not os.path.exists(filepath)):
                        continue
                    result = analysis.checkfile(filepath)
                    if result:
                        link = os.readlink(filepath)
                        self.suspicious_proc.append([filepath,link])
            end = len(self.suspicious_proc)
            return True if ini == end else False
        except:
            return True
    
    def shell_check(self):
        try:
            ini = len(self.suspicious_proc)
            if not os.path.exists("/proc/"):
                return True
            for files in os.listdir("/proc/"):
                if files.isdigit():
                    filepath = os.path.join("%s%s%s" % ("/proc/", files, "/cmdline"))
                    if not os.path.exists(filepath):continue
                    sub_file = open(filepath,"rb")
                    s = sub_file.read()
                    sub_file.close()
                    s = (s.replace(b"\0",b" ")).decode("utf8")
                    result = check_all.check_shell(s)
                    if result:
                        self.suspicious_proc.append([filepath,s])
            end = len(self.suspicious_proc)
            return True if ini == end else False
        except Exception as e:
            print(e)
            return True
    
    def cpu_mem_check(self):
        def mem_usage():
            if not os.path.exists("/proc/meminfo"):
                return False
            with open("/proc/meminfo") as meminfo:
                for line in meminfo:
                    if "MemTotal" in line:
                        memtotal = int(re.search(r"\d+",line).group())
                    if "MemFree" in line:
                        memfree = int(re.search(r"\d+",line).group())
            return (memtotal-memfree)/memtotal
        def cpu_usage():
            if not os.path.exists("/proc/stat"):
                return False
            last_idle = last_total = 0
            for i in range(2):
                with open('/proc/stat') as f:
                    fields = [float(column) for column in f.readline().strip().split()[1:]]
                idle, total = fields[3], sum(fields)
                idle_delta, total_delta = idle - last_idle, total - last_total
                last_idle, last_total = idle, total
                utilisation = 100.0 * (1.0 - idle_delta / total_delta)
                time.sleep(0.1)
            return utilisation
        ini = len(self.suspicious_proc)
        mem_usage = mem_usage()
        cpu_usage = cpu_usage()
        if mem_usage > 70:
            self.suspicious_proc.append(["/proc/meminfo","Memory Uasge Over 70%"])
        if cpu_usage > 70:
            self.suspicious_proc.append(["/proc/stat", "CPU Uasge Over 70%"])
        end = len(self.suspicious_proc)
        return True if ini == end else False

    def run(self):
        print(u'\n\033[1;33m%s\033[0m' % self.name)
        print(u'  %s%s' % (align("[1]exe check"), printf(self.exe_check())))
        print(u'  %s%s' % (align("[2]shell check"), printf(self.shell_check())))
        print(u'  %s%s' % (align("[3]cpu mem check"), printf(self.cpu_mem_check())))
        for detail in self.suspicious_proc:
            print(u'    [*]File:%s[*]Detail:%s' % (align(detail[0]), detail[1]))
