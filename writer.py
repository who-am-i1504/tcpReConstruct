import asyncio
import aiofiles
import os
import queue
from typing import Tuple
from concurrent.futures import ThreadPoolExecutor
from typing_extensions import Buffer
import threading

THRESHOLD_FOR_WRITER = 20
THREAD_POOL_FOR_WRITER = ThreadPoolExecutor(max_workers=20)


class NIOWriter:

    def __init__(self, que_size=10000, dir=None, sema_num=THRESHOLD_FOR_WRITER,
                 max_thread_num=THRESHOLD_FOR_WRITER):
        self.queue = queue.Queue(maxsize=que_size)
        self.thread_num = 0
        self.max_thread_num = max_thread_num
        self.executor = THREAD_POOL_FOR_WRITER
        self.loop = asyncio.new_event_loop()
        self.semaphore = asyncio.Semaphore(sema_num)
        self.dic = {}
        self.tag_que = queue.Queue(maxsize=sema_num)
        self.tag = False
        self._lock_for_dic = threading.Lock()
        self.task = []
        self.dir_path = dir

    def _is_empty_content(self, data):
        if data is None:
            return True
        if len(data) == 0:
            return True
        return all(len(d) == 0 for d in data) if isinstance(data, list) else False

    async def write(self, abs_file_path):
        data = self.get_data_list_from_dic(abs_file_path)
        if self._is_empty_content(data):
            self.task_done()
            return
        async with aiofiles.open(abs_file_path,
                                 'ab+', executor=self.executor) as f, self.semaphore:
            while not self._is_empty_content(data):
                if isinstance(data, list):
                    for d in data:
                        if len(d) == 0:
                            continue
                        await f.write(d)
                else:
                    await f.write(data)
                data = self.get_data_list_from_dic(abs_file_path)
            await f.close()
        self.queue.task_done()

    def get_data_list_from_dic(self, abs_file_path):
        try:
            self._lock_for_dic.acquire()
            data_list = self.dic.pop(abs_file_path, None)
            if not self._is_empty_content(data_list):
                self.dic[abs_file_path] = []
            else:
                self.thread_num -= 1
            return data_list
        finally:
             self._lock_for_dic.release()

    def start_loop(self):
        self.loop.create_task(self.main())
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_forever()
        except Exception as e:
            print(e)
        finally:
            self.loop.close()

    def add_in_loop(self, abs_file_path):
        loop = asyncio.get_running_loop()
        task = loop.create_task(self.write(abs_file_path))
        self.task.append(task)

    async def main(self):
        while True:
            if self.queue.empty():
                if self.tag:
                    self._lock_for_dic.acquire()
                    try:
                        if len(self.dic) == 0:
                            self.loop.stop()
                            break
                    finally:
                        self._lock_for_dic.release()
                if not self.tag_que.empty():
                    if self.tag_que.get():
                        self.tag = True
                    self.tag_que.task_done()
                await asyncio.sleep(0.1)
                continue
            while (not self.queue.empty()) and self.thread_num < self.max_thread_num:
                item = self.queue.get()
                abs_path, datas = item
                self._lock_for_dic.acquire()
                try:
                    if abs_path in self.dic:
                        self.dic[abs_path].extend(datas)
                    else:
                        self.dic[abs_path] = datas
                        self.add_in_loop(abs_path)
                        self.thread_num += 1
                finally:
                    self._lock_for_dic.release()
            await asyncio.sleep(self.  # The `thread_num` variable in the `NIOWriter` class is used to keep track of the number of threads currently running for writing data to files. It is incremented whenever a new write operation is started and decremented when a write operation is completed. This variable is used to control the maximum number of concurrent write operations that can be running at the same time, based on the `max_thread_num` set during initialization of the `NIOWriter` instance.
                                thread_num / 100)

    def put(self, file_name: str, datas: list | Buffer | bytes | str):
        queue_item: Tuple[str, list | Buffer | bytes | str] = file_name, datas
        if self.dir_path is not None:
            queue_item: Tuple[str, list | Buffer | bytes | str] = os.path.join(
                self.dir_path, file_name), datas
        self.queue.put(queue_item)

    def quit(self):
        if not self.tag_que.full():
            self.tag_que.put(True)
