import asyncio
import aiofiles
import os
import queue
from typing import Tuple
from concurrent.futures import ThreadPoolExecutor
from typing_extensions import Buffer
import threading
try:
    from BytesIO import BytesIO
except ImportError:
    from io import BytesIO

THRESHOLD_FOR_WRITER = 20
THREAD_POOL_FOR_WRITER = ThreadPoolExecutor(max_workers=THRESHOLD_FOR_WRITER)


class NIOWriter:

    def __init__(self, que_size=1000000, dir=None, sema_num=THRESHOLD_FOR_WRITER):

        self.queue = queue.Queue(maxsize=que_size)
        self.executor = THREAD_POOL_FOR_WRITER
        self.dic = {}
        self.tag_que = asyncio.Queue(maxsize=sema_num)
        self.tag = False
        self._lock_for_dic = asyncio.Lock()
        self.dir_path = dir
        self.loop = asyncio.new_event_loop()
        self.task_dic = {}

    def _is_empty_content(self, data):
        if data is None:
            return True
        if len(data) == 0:
            return True
        return all(self._is_empty_for_item(d) for d in data) if isinstance(data, list) else False

    def _is_empty_for_item(self, data_item) -> bool:
        if isinstance(data_item, BytesIO):
            return data_item.tell() == 0
        return len(data_item) == 0

    async def write(self, abs_file_path):
        data = await self.get_data_list_from_dic(abs_file_path)
        if self._is_empty_content(data):
            return
        async with aiofiles.open(abs_file_path,
                                 'ab+') as f:
            while not self._is_empty_content(data):
                await self.write_to_file(data, f)
                data = await self.get_data_list_from_dic(abs_file_path)

    async def write_to_file(self, data, f):
        if isinstance(data, list):
            for d in data:
                if self._is_empty_for_item(d):
                    continue
                await self.write_to_file(d, f)
            return
        if isinstance(data, bytes):
            await f.write(data)
            return
        
        if isinstance(data, BytesIO):
            await f.write(data.read())
            data.close()

    async def get_data_list_from_dic(self, abs_file_path):
        async with self._lock_for_dic:
            data = self.dic.pop(abs_file_path, None)
            if self._is_empty_content(data):
                self.task_dic.pop(abs_file_path, None)
            return data

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
        if abs_file_path not in self.task_dic:
            self.task_dic[abs_file_path] = []
        loop = asyncio.get_running_loop()
        self.task_dic[abs_file_path].append(
            loop.create_task(self.write(abs_file_path)))

    async def main(self):
        while True:
            if self.queue.empty() and self.tag:
                task_list = []
                async with self._lock_for_dic:
                    for value in self.task_dic.values():
                        task_list.extend(value)
                await self.loop.gather(*task_list, return_exceptions=True)
            if not self.tag_que.empty():
                self.tag = await self.tag_que.get()
                self.tag_que.task_done()
            while not self.queue.empty():
                abs_path, datas = self.queue.get()
                self.queue.task_done()
                async with self._lock_for_dic:
                    if abs_path in self.dic:
                        self.dic[abs_path].extend(datas)
                    else:
                        self.dic[abs_path] = datas
                        self.add_in_loop(abs_path)
            await asyncio.sleep(0.01)

    def put(self, file_name: str, datas: list | Buffer | bytes | str):
        queue_item: Tuple[str, list | Buffer | bytes | str] = file_name, datas
        if self.dir_path is not None:
            queue_item: Tuple[str, list | Buffer | bytes | str] = os.path.join(
                self.dir_path, file_name), datas
        self.queue.put_nowait(queue_item)

    def quit(self):
        if not self.tag_que.full():
            self.tag_que.put(True)
