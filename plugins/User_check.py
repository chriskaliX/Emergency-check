import os
from plugins.common.common import printf,align
class User_check:
    def __init__(self):
        self.suspicious_user = []
        self.name = u'User Security check'
    
    #check_root_user
    def root_check(self):
        ini_len = len(self.suspicious_user)
        try:
            for user in open('/etc/passwd','r').readlines():
                user = user.replace("\n","")
                user_list = user.split(":")
                if ((user_list[2] == '0') and (user_list[0] != "root")):
                    self.suspicious_user.append(["/etc/passwd", user])
            end_len = len(self.suspicious_user)
            return False if end_len > ini_len else True
        except:return True

    #check_empty_user
    def empty_check(self):
        ini_len = len(self.suspicious_user)
        try:
            for user in open('/etc/shadow','r').readlines():
                user = user.replace("\n","")
                user_list = user.split(":")
                if user_list[1] == "":
                    self.suspicious_user.append(['/etc/shadow',user])
            end_len = len(self.suspicious_user)
            return False if end_len > ini_len else True
        except:return True

    #sudo_check
    def sudo_check(self):
        ini_len = len(self.suspicious_user)
        try:
            for user in open('/etc/sudoers','r').readlines():
                user = user.replace("\n","")
                if user[0] == "%":continue
                if "ALL=(ALL)" in user:
                    user_list = user.split("\t")
                    if user_list[0] != "root":
                        self.suspicious_user.append(["/etc/sudoers",user])
            end_len = len(self.suspicious_user)
            return False if end_len > ini_len else True
        except:return True

    #authorized_keys_check
    def authorized_check(self):
        ini_len = len(self.suspicious_user)
        try:
            for sub_dir in os.listdir("/home/"):
                full_sub_dir = os.path.join('%s%s%s' % (
                    "/home/", sub_dir, "/.ssh/authorized_keys"))
                for user in open(full_sub_dir,'r').readlines():
                    user = user.replace("\n","")
                    user_list = user.split(" ")
                    if user_list[2]:
                        self.suspicious_user.append([full_sub_dir,user_list[2]])
            for user in open("/root/.ssh/authorized_keys").readlines():
                user = user.replace("\n","")
                user_list = user.split(" ")
                if user_list[2]:
                    self.suspicious_user.append(["/root/.ssh/authorized_keys",user_list[2]])
            end_len = len(self.suspicious_user)
            return False if end_len > ini_len else True
        except:return True

    #permission_check
    def permission_check(self):
        ini_len = len(self.suspicious_user)
        try:
            passwd = oct(os.stat("/etc/passwd").st_mode)[-3:]
            shadow = oct(os.stat("/etc/shadow").st_mode)[-3:]
            if passwd != "644":self.suspicious_user.append(["/etc/passwd",passwd])
            if shadow > "640":self.suspicious_user.append(["/etc/shadow",shadow])
            end_len = len(self.suspicious_user)
            return False if end_len > ini_len else True
        except:return True

    #run them all
    def run(self):
        print(u"\n\033[1;33m%s\033[0m" % self.name)
        print(u"  %s%s" % (align("[1]root user check"),printf(self.root_check())))
        print(u"  %s%s" % (align("[2]empty passwd check"),printf(self.empty_check())))
        print(u"  %s%s" % (align("[3]sudoer check"),printf(self.sudo_check())))
        print(u"  %s%s" % (align("[4]authorized check"),printf(self.authorized_check())))
        print(u"  %s%s" % (align("[5]passwd file check"),printf(self.permission_check())))
        for detail in self.suspicious_user:
            print(u"    [*]File:%sDetail:%s"%(align(detail[0]),detail[1]))