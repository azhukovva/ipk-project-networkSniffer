from __future__ import annotations
import json
import os
from platform import system
import subprocess as sp

from typing import TypedDict, Final

from pkg import Neighbour
from pkg.differ import compare

TIMEOUT: Final = 10  # seconds


class TestClient:
    Test: TypedDict = TypedDict("Test", {
        "mode": str,
        "message": str,
        "host": str,
        "port": int,
        "in": str,
        "out": str,
        "err": str,
        "interface": str,
        "code": int,
        "n": int,
    })

    def parse_tests(self) -> list:
        tests = []

        defaults: dict = {
            "host": "192.168.0.99",
            "port": None,
            "message": "make Koutensky not war",
            "err": "",
            "out": "",
            "interface": "eth0" if system() == "Linux" else "en0",
            "code": 0,
            "n": 1,
        }

        for file in os.listdir(self.directory):
            if file.endswith(".json"):
                defaults["mode"] = file.split(".")[0]
                with open(f"{self.directory}/{file}", "r") as f:
                    test = json.loads(f.read())
                    for field in ["mode", "message", "host", "port", "in", "out", "err", "interface", "code"]:
                        if field not in test:
                            try:
                                test[field] = defaults[field]
                            except KeyError:
                                print(f"Error: {field} not found in {file}. Skipping...")
                                continue
                    tests.append(test)
        return tests

    def __init__(self, sniffer=None, tests=None):
        self.nb = Neighbour("192.168.0.1", 8080)
        self.directory = tests or "tests"
        self.sniffer = sniffer or "ipk-sniffer"
        self.tests = self.parse_tests()
        self.comparer = compare

    def set_comparer(self, comparer):
        self.comparer = comparer

    def start_sniffer(self, flags):
        return sp.Popen(f"./{self.sniffer} {flags}", shell=True, stdout=sp.PIPE, stderr=sp.PIPE)

    def dump(self, stream, expected: str | bytes, actual: str | bytes, only_header=True):
        print(f"--- {stream} ---")
        if isinstance(expected, bytes):
            expected = expected.decode()

        if isinstance(actual, bytes):
            actual = actual.decode()

        header = actual.splitlines()[3:9]
        header.pop(1)
        header.pop(2)
        self.comparer(expected, "\n".join(header) if only_header else actual)

    def read_expected_file(self, file):
        with open(f"{self.directory}/{file}", 'r') as fd:
            return fd.read()

    def run(self):
        for test in self.tests:  # type: TestClient.Test
            flags = f"{'-i ' + test['interface'] if test['interface'] else ''} " \
                    f"{test['mode'] or ''} " \
                    f"{'-p ' + str(test['port']) if test['port'] else ''} " \
                    f"{('-n ' + str(test['n'])) if test['n'] else ''}"
            sniffer = self.start_sniffer(
                flags
            )
            print(flags)

            self.nb.send_packet(test["mode"].strip("-"), test["message"], test["host"], test["port"])

            out, err = sniffer.communicate(timeout=TIMEOUT)
            self.dump("stdout", self.read_expected_file(test["out"]), out)
            if not test["code"] or sniffer.returncode or err:  # if we expect an error or sniffer returned an error
                self.dump("stderr", err, test["err"])


if __name__ == "__main__":
    # run tests
    client = TestClient()
    client.run()
