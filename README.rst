WAF Benchmark - And way to measure the Web Application Firewalls
================================================================

+----------------+-------------------------------------------------------+
|Project site    | https://github.com/bbva/waf-benchmark                 |
+----------------+-------------------------------------------------------+
|Issues          | https://github.com/bbva/waf-benchmark                 |
+----------------+-------------------------------------------------------+
|Latest Version  | 1.0.0-alpha                                           |
+----------------+-------------------------------------------------------+
|Python versions | 3.6 or above                                          |
+----------------+-------------------------------------------------------+
|License         | Apache 2                                              |
+----------------+-------------------------------------------------------+


Overview
========

This project was born to try to create a way to measure the WAF efficiency.

Currently there're a lot of WAF and a lot of papers and articles about how to good or bad are each available options, but there's not a standard way to test each WAF following these requisites:

The test must be:

- Must be repeatable
- Must measure a do all the test to each product that want to test
- Must be automatic
- Must be measurable the results
- Must know what


Supported attacks
=================

- SQl Injection


Usage
=====

Working modes
-------------

- Testing mode: use

How install
-----------
.. highlight:: bash
pip install -e .

How use
-------
1. Launch the waf server and the application server
---------------------------------------------------
`This is a example repo for launch modsecurity server with express server <https://github.com/theonemule/docker-waf>`

2. Launch waf-benchmark over the waf server address
---------------------------------------------------
You have multiples kind of benchmarking
- For demo you can limit the number of results and list payloads summary
.. highlight:: bash
python -m  waf_benchmark http://localhost:8000 --list-payloads -M 2
- List all benchmarks
.. highlight:: bash
python -m  waf_benchmark http://localhost:8000 --list-payloads
- This can take a long time(~ 55000 requests), send the output to a file
.. highlight:: bash
python -m  waf_benchmark http://localhost:8000 --list-payloads >> output_bench.txt

