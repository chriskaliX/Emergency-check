from plugins.common.common import allfile
import threading

class go:
    def __init__(self):
        self.file_list = []
        self.dir_list = []

    def init(self):
        start = allfile()
        start.run()
        self.file_list = start.files
        self.dir_list = start.dirs

init = go()