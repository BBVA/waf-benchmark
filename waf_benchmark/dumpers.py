from typing import Tuple, Dict

from terminaltables import AsciiTable
from collections import Counter, defaultdict
from waf_benchmark.model import WAFBenchRunningConfig


def _calculate(results: Dict[str, Tuple[Tuple[str, str, str]]]):
    total = Counter()
    total_success = Counter()
    total_blocked = Counter()
    success_attacks = defaultdict(list)

    for attack_type, content in results.items():

        for c in content:
            tool_name, payload, http_code = c

            total_blocked[tool_name] += 1 if http_code == 403 else 0
            total[tool_name] += 1

            if str(http_code).startswith("2"):
                total_success[tool_name] += 1
                success_attacks[tool_name].append(payload)

    return total, total_success, total_blocked, success_attacks


def dump_screen(results: Dict[str, Tuple[Tuple[str, str, str]]],
                config: WAFBenchRunningConfig):
    cols = [["Tool name", "Attacks blocked", "Success attacks"]]

    #
    # total payloads, payloads ok, payload fails
    #
    total, total_success, total_blocked, success_attacks = _calculate(results)

    print("\nResults:\n")
    for attack_type, content in results.items():

        print(f"Attack type: {attack_type}")
        print("=" * len(f"Attack type: {attack_type}"))
        print()

        for c in content:
            tool_name, payload, http_code = c

            total_blocked[tool_name] += 1 if http_code == 403 else 0
            total[tool_name] += 1

            if str(http_code).startswith("2"):
                total_success[tool_name] += 1
                success_attacks[tool_name].append(payload)

        for tool_name in total.keys():
            cols.append([
                tool_name,
                total_blocked[tool_name],
                total_success[tool_name]
            ])

        t = AsciiTable(cols)
        print(t.table)

        #
        # Show successful attacks
        #
        if config.list_payload:
            print()
            print(f"Successful {attack_type} attacks:\n")
            for tool_name, payloads in success_attacks.items():

                print(f"  > {tool_name}:")
                for payload in payloads:
                    print(f"    -> {payload}")

                print()



DUMPERS = {
    'screen': dump_screen
}


def dump(content: Tuple[Tuple[str, str, str]],
         config: WAFBenchRunningConfig):

    DUMPERS[config.dump_mode](content, config)


__all__ = ("dump", "DUMPERS")
