# Copyright 2020 Wesley Shields <wxs@atarininja.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import argparse
import asyncio
import json
import os
import re

import aiohttp


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch files from VT for yrrc")
    parser.add_argument(
        "-c", "--config", type=open, default="config.json", help="Config file"
    )
    return parser.parse_args()


def get_hashes_json(hashes_file):
    try:
        with open(hashes_file, "r") as f:
            return json.loads(f.read())
    except Exception as e:
        print(e)
        return


async def future_fetch(cache_dir, sample, url, session):
    async with session.get(url) as response:
        print(f"{sample} {response.status}")
        if response.status == 200:
            with open(os.path.join(cache_dir, sample), "wb") as f:
                while True:
                    chunk = await response.content.read(1024 * 10)
                    if not chunk:
                        break
                    f.write(chunk)


async def fetch_samples(samples, vt_key, cache_dir):
    cached = os.listdir(cache_dir)
    async with aiohttp.ClientSession(headers={"X-apikey": vt_key}) as session:
        tasks = [
            asyncio.ensure_future(
                future_fetch(
                    cache_dir,
                    sample,
                    f"https://www.virustotal.com/api/v3/files/{sample}/download",
                    session,
                )
            )
            for sample in samples
            if sample not in cached
        ]
        await asyncio.gather(*tasks)


async def main():
    args = parse_args()
    try:
        config = json.loads(args.config.read())
        cache_dir = config["cache_dir"]
        hashes_file = config["hashes_file"]
        vt_key = config["vt_key"]
    except json.JSONDecodeError as e:
        print(f"Error decoding config: {e}")
        return
    except KeyError as e:
        print(f"Error reading config: {e}")
        return

    if not os.path.isdir(cache_dir):
        print("Cache directory does not exist")
        return

    hashes_json = get_hashes_json(hashes_file)
    if not hashes_json:
        print("No hashes file to parse")
        return

    with open(vt_key, "r") as f:
        vt_key = f.read()

    re_hash = re.compile(r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
    await fetch_samples(
        set([k for k in hashes_json.keys() if re_hash.match(k)]),
        vt_key,
        cache_dir,
    )


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
