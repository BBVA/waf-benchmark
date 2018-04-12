import argparse

from waf_benchmark.dumpers import DUMPERS, dump
from waf_benchmark.exceptions import WAFBenchmark
# from waf_benchmark.attack_curio import launch_benchmark
from waf_benchmark.attack import launch_benchmark
from waf_benchmark.model import WAFBenchRunningConfig


def build_parser():
    parser = argparse.ArgumentParser(
        description='WAF-Bench: a benchmarking test for WAF systems',
        formatter_class=argparse.RawTextHelpFormatter)

    # Main options
    parser.add_argument(dest="WAF_URL",
                        help="Application access",
                        default="http://127.0.0.1:8080")
    parser.add_argument("-v", "--verbosity", dest="verbosity", action="count",
                        help="verbosity level: -v, -vv, -vvv.", default=3)

    output = parser.add_argument_group("Output options")
    output.add_argument(
        '-c', '--concurrency',
        help="maximum concurrency (default: 50)",
        default=50
    )
    output.add_argument(
        '-D', '--dump-mode',
        nargs="+",
        help="how to dump the information (default: screen)",
        choices=DUMPERS.keys(),
        default="screen"
    )
    output.add_argument(
        '-p', '--list-payloads',
        action="store_true",
        help="list payloads that a WAF can't block (default: False)",
        default=False
    )
    output.add_argument(
        '-o', '--dump-file',
        help="file path to dump results",
        default="dump.txt"
    )
    output.add_argument(
        '-S',
        dest="check_connection",
        action="store_false",
        help="don't check connection to WAF "
             "before start tests (default: False)",
        default=True
    )
    output.add_argument(
        '-M', '--maximum-attacks',
        help="maximum number of attacks to do per data set (default: all)",
        default=0
    )

    # Main options
    return parser


def main():
    parser = build_parser()
    parsed = parser.parse_args()

    # Load config
    config = WAFBenchRunningConfig.from_argparser(parsed)

    try:
        print(f"[*] Starting benchmarking to: '{config.waf_url}'")
        results = launch_benchmark(config)

        #
        # Manage results
        #
        dump(results, config)

    except WAFBenchmark as e:
        print()
        print(f"[!] {e}")
        print()
    except KeyError as e:
        print("[!] Invalid action: ", e)
        return
    except KeyboardInterrupt:
        print("Finishing...")


if __name__ == '__main__':
    main()
