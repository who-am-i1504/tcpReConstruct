import asyncio
import aiofiles
import os
import queue
from concurrent.futures import ThreadPoolExecutor
import threading

threshold = 20
threadPool = ThreadPoolExecutor(max_workers=20)
class NIOWriter:

    def __init__(self, queSize=10000, semaNumber=threshold, maxThreadNum = threshold, executor=threshold-1):
        self.queue = queue.Queue(maxsize=queSize)
        self.threadNum = 0
        self.maxThreadNum = maxThreadNum
        # if executor is None:
        #     self.executor = None
        # else:
        #     self.executor = ThreadPoolExecutor(max_workers=executor)
        # self.executor.submit(calcute)
        self.executor = threadPool
        self.loop = asyncio.new_event_loop()
        self.sema = asyncio.Semaphore(semaNumber,loop=self.loop)
        # self.loop.set_default_executor(self.executor)
        self.dic = {}
        self.tagQue = queue.Queue(maxsize=semaNumber)
        self.Tag = False
        self._lock_for_dic = threading.Lock()
        self.task = []

    async def write(self, absPath, fileName, data):
        length = 0
        for i in data:
            if isinstance(i, list):
                for j in i:
                    if len(j) == 0:
                        continue
                    else:
                        length = 1
                        break
                continue
            if (not len(i) == 0) or length == 1:
                length = 1
                break
        if length > 0:
            async with aiofiles.open(os.path.join(absPath, fileName), 'ab+', executor=self.executor) as f, self.sema:
                if isinstance(data, list):
                    while len(data) > 0:
                        i = data.pop(0)
                        if len(i) == 0:
                            continue
                        if isinstance(i, list):
                            for j in i:
                                # await f.write(j.tcp_payload)
                                await f.write(j)
                        else:
                            # await f.write(i.tcp_data)
                            await f.write(i)
                else:
                    await f.write(data)
                await f.close()
        self._lock_for_dic.acquire()
        try:
            self.dic.pop(os.path.join(absPath, fileName), None)
            self.threadNum -= 1
        finally:
            self._lock_for_dic.release()
        self.queue.task_done()
            # return 1

    def start_loop(self):
        
        self.loop.create_task(self.main())
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_forever()
        except Exception as e:
            print(e)
        finally:
            self.loop.close()

    def addInLoop(self, absPath, fileName, data):
        loop = asyncio.get_running_loop()
        task = loop.create_task(self.write(absPath, fileName, data))
        self.task.append(task)
        # task.add_done_callback(self.callback)
    
    # def callback(self, future):
        

    async def main(self):
        while True:
            if (not self.queue.empty()) and self.threadNum < self.maxThreadNum:
                while (not self.queue.empty()) and self.threadNum < self.maxThreadNum:
                    item = self.queue.get()
                    key = os.path.join(item['absPath'], item['fileName'])
                    self._lock_for_dic.acquire()
                    try:
                        if key in self.dic:
                            self.dic[key].append(item['data'])
                        else:
                            self.dic[key] = item['data']
                            self.addInLoop(item['absPath'], item['fileName'], item['data'])
                            self.threadNum += 1
                    finally:
                        self._lock_for_dic.release()
                await asyncio.sleep(self.threadNum / 100)
            else:
                if not self.tagQue.empty():
                    if self.tagQue.get():
                        self.Tag = True
                    self.tagQue.task_done()
                elif self.Tag:
                    self._lock_for_dic.acquire()
                    try:
                        if len(self.dic) == 0:
                            # print(len(self.dic))
                            self.loop.stop()
                            # if not self.executor is None:
                            #     self.executor.shutdown()
                            break
                    finally:
                        self._lock_for_dic.release()
                await asyncio.sleep(0.1)

    def put(self, item):
        self.queue.put(item)
    
    def quit(self):
        if not self.tagQue.full():
            self.tagQue.put(True)