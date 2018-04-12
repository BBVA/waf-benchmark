import curio
import curio_http
import uuid
import logging
import asyncio

import aiohttp
import os.path as op

from collections import defaultdict
from typing import Tuple, List, Dict

from waf_benchmark.exceptions import WAFBenchmark
from waf_benchmark.model import WAFBenchRunningConfig

log = logging.getLogger("waf-benchmark")

BASE_DATA_SETS = "datasets"
DATA_SETS_SQLI = (
    ('sqlmap', 'sqlmap.txt'),
    ('OWASP ZAP', 'zap.txt'),
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
                track_id: str):
    try:
        async with curio_http.ClientSession() as session:
            response = await session.get(url, headers={
                                   "WAF-BENCHMARK-TRACK-ID": track_id
                               })
            return response.status_code, track_id

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

    #
    # Check connection before start the tests
    #
    # if config.check_connection:
    #     if not await test_connection(session,
    #                                  url=f"{config.waf_url}/?id=1"):
    #         raise WAFBenchmark("Can't connect to the WAF")

    tasks_to_join = []

    for tool_name, data_set in data_sets:

        #
        # Track query with the payload
        #
        for c, payload in enumerate(data_set):

            if config.maximum_attacks != 0 and c == config.maximum_attacks:
                break

            track_id = uuid.uuid4().hex
            track_queries[track_id] = (payload, tool_name)

            tasks_to_join.append((f"{config.waf_url}/?id={payload}", track_id))

            if i % 1000 == 0:
                print(f"    - Launching case: {i}")

            if i % config.concurrency == 0:
                _tasks = []
                for (url, track_id) in tasks_to_join:
                    t = await curio.spawn(
                        fetch,
                        url,
                        track_id)
                    _tasks.append(t)

                    for tt in _tasks:
                        await tt.join()
                        track_responses.append(tt.result)

                tasks_to_join = []
            i += 1

    print("[*] Launching tests")

    #
    # Merge
    #
    merged = set()

    for res in track_responses:
        http_code, track_id = res
        payload, tool_name = track_queries[track_id]

        merged.add((tool_name, payload, http_code))

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
        # r = curio.run(do_attack(loaded_data_set, config))
        #
        # results[attack_type] = r

    return results


__all__ = ("launch_benchmark", )

