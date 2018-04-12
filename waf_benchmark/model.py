from argparse import Namespace


class WAFBenchRunningConfig:

    def __init__(self,
                 verbosity: bool,
                 waf_url: str,
                 dump_mode: str,
                 list_payload: bool,
                 concurrency: int,
                 maximum_attacks: int,
                 check_connection: bool,
                 dump_file: str):
        self.waf_url = waf_url
        self.dump_mode = dump_mode
        self.dump_file = dump_file
        self.verbosity = verbosity
        self.concurrency = int(concurrency)
        self.list_payload = list_payload
        self.maximum_attacks = int(maximum_attacks)
        self.check_connection = bool(check_connection)

    @classmethod
    def from_argparser(cls, argparser_input: Namespace):
        return WAFBenchRunningConfig(
            verbosity=argparser_input.verbosity,
            maximum_attacks=argparser_input.maximum_attacks,
            waf_url=argparser_input.WAF_URL,
            check_connection=argparser_input.check_connection,
            concurrency=argparser_input.concurrency,
            dump_mode=argparser_input.dump_mode,
            list_payload=argparser_input.list_payloads,
            dump_file=argparser_input.dump_file
        )


__all__ = ("WAFBenchRunningConfig",)
