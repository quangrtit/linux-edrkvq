import asyncio
import aiohttp

URL = "http://httpbin.org/get"
CONCURRENCY = 30
REQUESTS_PER_TASK = 1000
BATCH_SIZE = 50


async def fetch(session: aiohttp.ClientSession, task_id: int, req_id: int):
    try:
        async with session.get(URL) as resp:
            await resp.read()
            print(f"[Task {task_id}] Request {req_id} -> {resp.status}")
    except Exception as e:
        print(f"[Task {task_id}] Request {req_id} failed: {e}")


async def spam_task(task_id: int, session: aiohttp.ClientSession):
    req_id = 0
    while req_id < REQUESTS_PER_TASK:
        batch = [
            fetch(session, task_id, req_id + i)
            for i in range(BATCH_SIZE)
        ]
        await asyncio.gather(*batch)
        req_id += BATCH_SIZE


async def main():
    conn = aiohttp.TCPConnector(limit=0)
    timeout = aiohttp.ClientTimeout(total=None)

    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        tasks = [spam_task(i, session) for i in range(1, CONCURRENCY + 1)]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
