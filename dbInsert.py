import os
import asyncio
import aiohttp
import json

DB_URL = os.environ.get('BUNNY_DB_URL', None)
DB_TOKEN = os.environ.get('BUNNY_DB_TOKEN', None)

async def log_spf_result(domain: str, ip: str, result: str, ipversion: int):
    query = """
        INSERT INTO spf_results (domain, ip, result, ipversion)
        VALUES (?1, ?2, ?3, ?4);
    """

    data = {
        "statements": [
            {
                "q": query,
                "params": [domain, ip, result, ipversion]
            }
        ]
    }

    headers = {
        "Authorization": f"Bearer {DB_TOKEN}",
        "Content-Type": "application/json"
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(DB_URL, headers=headers, data=json.dumps(data)) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"DB insert failed: {resp.status} | {text}")
            return True


async def main():
    await log_spf_result("example.com", "203.0.113.10", "pass", 4)
    print("Inserted OK")

if __name__ == "__main__":
    asyncio.run(main())
