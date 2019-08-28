import os
from plugins.common.Analysis import analysis
from plugins.common.common import printf,align
class History_check:
    def __init__(self):
        self.suspicious_history = []
        self.name = u'History Security Check'
    def history_files(self):
        try:
            file_path = ['/home/','/root/.bash_history','/Users/']
            for path in file_path:
                if not os.path.exists(path):continue
                if os.path.isdir(path):
                    for sub_dir in os.listdir(path):
                        sub_file = os.path.join("%s%s%s" % (path,sub_dir,'/.bash_history'))
                        if not os.path.exists(sub_file):continue
                        for line in open(sub_file,'r').readlines():
                            line = line.replace("\n","")
                            contents = analysis.history(line)
                            if contents:
                                self.suspicious_history.append([sub_file,line])
                else:
                    with open(path,'r') as f:
                        for line in f:
                            line = line.replace("\n", "")
                            contents = analysis.history(line)
                            if contents:
                                self.suspicious_history.append([path,line])
            return True if self.suspicious_history == [] else False
        except:
            return True
    def run(self):
        print(u'\n\033[1;33m%s\033[0m' % self.name)
        print(u"  %s%s" % (align("[1]History file check"),printf(self.history_files())))
        for detail in self.suspicious_history:
            print("    [*]File:%sDetail:%s"%(align(detail[0]),detail[1]))
