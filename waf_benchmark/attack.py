import uuid
import logging
import asyncio
import concurrent.futures.process

import aiohttp
import os.path as op

from aiohttp import ClientSession
from collections import defaultdict
from typing import Tuple, List, Dict

from waf_benchmark.exceptions import WAFBenchmark
from waf_benchmark.model import WAFBenchRunningConfig

log = logging.getLogger("waf-benchmark")

BASE_DATA_SETS = "datasets"
DATA_SETS_SQLI = (
    ('sqlmap', 'sqlmap.txt'),
    ('OWASP ZAP', 'zap.txt'),
    ('Darkweb 2017 Top 10000', 'darkweb2017-top10000.txt'),
    ('Family Names USA Top 1000', 'familynames-usa-top1000.txt'),
    ('Female Names USA Top 1000', 'femalenames-usa-top1000.txt'),
    ('Male Names USATop 1000', 'malenames-usa-top1000.txt'),
    ('Names', 'names.txt'),
)

ATTACKS_TYPES = (
    ('sqli', DATA_SETS_SQLI),
)


async def test_connection(session, url) -> bool:
    try:
        async with session.get(url) as response:
            if response.status == 200:
                return True
            else:
                return False
    except aiohttp.client_exceptions.ClientConnectorError:
        return False


async def fetch(url,
                session,
                track_id: str):
    try:
        async with session.get(url,
                               headers={
                                   "WAF-BENCHMARK-TRACK-ID": track_id
                               }) as response:

            return response.status, track_id

    except Exception as e:
        log.info(f"ERROR :: {e} :: {url}")
        print(f"ERROR :: {e} :: {url}")
        raise WAFBenchmark(e)


async def do_attack(data_sets: List[Tuple[str, List[str]]],
                    config: WAFBenchRunningConfig):
    """
    Return a tuple as the format:

    (tool-name, payload, http response code)

    """

    i = 1
    track_queries = {}
    track_responses = []
    track_responses_extend = track_responses.extend
    async with ClientSession() as session:

        #
        # Check connection before start the tests
        #
        if config.check_connection:
            if not await test_connection(session,
                                         url=f"{config.waf_url}/?id=1"):
                raise WAFBenchmark("Can't connect to the WAF")

        tasks = []
        for tool_name, data_set in data_sets:

            #
            # Track query with the payload
            #
            for c, payload in enumerate(data_set):

                if config.maximum_attacks != 0 and c == config.maximum_attacks:
                    break

                track_id = uuid.uuid4().hex
                track_queries[track_id] = (payload, tool_name)

                tasks.append(fetch(
                    f"{config.waf_url}/?id={payload}",
                    session,
                    track_id
                ))

                if i % 1000 == 0:
                    print(f"    - Launching case: {i}")

                # -------------------------------------------------------------------------
                # Only launch when we have concurrency number
                # -------------------------------------------------------------------------
                if i % config.concurrency == 0:
                    track_responses_extend(await asyncio.gather(
                        *tasks,
                        return_exceptions=True))
                    tasks = []

                i += 1

        # Executing remaining tasks
        if tasks:
            track_responses_extend(await asyncio.gather(
                *tasks,
                return_exceptions=True))
        print("[*] Launching tests")

    #
    # Merge
    #
    merged = []

    for res in track_responses:
        http_code, track_id = res
        payload, tool_name = track_queries[track_id]

        merged.append((tool_name, payload, http_code))

    return merged


def launch_benchmark(config: WAFBenchRunningConfig) -> \
        Dict[str, Tuple[Tuple[str, str, str]]]:

    here = op.dirname(__file__)

    loaded_data_sets = defaultdict(list)

    #
    # Because loading file from disk is not asyncio and will block all the
    # coroutines, first of all -> load all the data
    #
    for (attack_type, dataset) in ATTACKS_TYPES:
        for (tool_name, file_name) in dataset:

            with open(op.join(here,
                              "datasets",
                              attack_type,
                              file_name), "r") as f:
                loaded_data_sets[attack_type].append((
                    tool_name,
                    f.read().splitlines()
                ))

    loop = asyncio.get_event_loop()
    #
    # Do attacks for each kind of attack
    #
    results = {}
    for attack_type, loaded_data_set in loaded_data_sets.items():
        results[attack_type] = loop.run_until_complete(
            do_attack(loaded_data_set, config)
        )

    return results


__all__ = ("launch_benchmark", )

