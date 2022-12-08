#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Blocky4 async iptables handling module"""

import asyncio
import sys
import re
import netaddr
import typing
import shutil

MAX_IPTABLES_TRIES = 10  # If we can't get iptables to unlock after 10 retries, it's hosed. Give up
ENV_EXEC = "/usr/bin/env"
IPTABLES_EXEC = shutil.which("iptables")
IP6TABLES_EXEC = shutil.which("ip6tables")


class Entry:
    """An iptables entry in a chain"""

    def __init__(self, chain, line_number, action, protocol, option, source, destination, extensions):
        self.chain = chain
        self.line_number = line_number
        self.action = action
        self.protocol = protocol
        self.option = option
        self.source = source
        self.as_net = netaddr.IPNetwork(source)
        self.destination = destination
        self.extensions = extensions

    def __repr__(self):
        return str(self.as_net)

    def __hash__(self):
        return self.as_net

    def __eq__(self, other):
        if isinstance(other, Entry):
            return self.as_net == other.as_net
        if isinstance(other, netaddr.IPNetwork):
            return self.as_net == other
        if isinstance(other, str):
            return self.source == other or str(self.as_net) == other
        return False

    def to_dict(self):
        return {
            "chain": self.chain,
            "line_number": self.line_number,
            "action": self.action,
            "protocol": self.protocol,
            "option": self.option,
            "source": self.source,
            "destination": self.destination,
            "extensions": self.extensions,
        }


class Chain:
    """An iptables chain with a name and a set of rules"""

    def __init__(self, chain="INPUT"):
        self.chain = chain
        self.items = []

    async def refresh(self):
        """Gets a list of all bans in a chain, according to iptables"""
        chain_list = []

        # Get IPv4 list
        for i in range(0, MAX_IPTABLES_TRIES):
            out = None
            try:
                proc = await asyncio.subprocess.create_subprocess_exec(
                    ENV_EXEC,
                    IPTABLES_EXEC,
                    "--list",
                    self.chain,
                    "-n",
                    "--line-numbers",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                assert proc.returncode == 0, stderr
                out = stdout
            except AssertionError as err:
                if "you must be root" in str(err) or "Permission denied" in str(err):
                    print(
                        "Looks like blocky doesn't have permission to access iptables, giving up completely! (are you "
                        "running as root?)"
                    )
                    sys.exit(-1)
                if "No chain/target/match" in str(err):
                    continue
                await asyncio.sleep(1)  # write lock, probably
            if out:
                for line in out.decode("ascii").split("\n"):
                    m = re.match(
                        r"^(\d+)\s+([-0-9a-zA-Z]+)\s+(all|tcp|udp)\s+(\S+)\s+([0-9a-f.:/]+)\s+([0-9a-f.:/]+)\s*(.*?)$", line
                    )
                    if m:
                        line_number = m.group(1)
                        action = m.group(2)
                        protocol = m.group(3)
                        option = m.group(4)
                        source = m.group(5)
                        destination = m.group(6)
                        extensions = m.group(7)
                        if action and action not in ["DROP", "REJECT"]:   # We only want drops and rejects
                            continue
                        entry = Entry(
                            self.chain, line_number, action, protocol, option, source, destination, extensions
                        )

                        chain_list.append(entry)
                break
        # Get IPv6 list
        if IP6TABLES_EXEC:
            for i in range(0, MAX_IPTABLES_TRIES):
                try:
                    proc = await asyncio.subprocess.create_subprocess_exec(
                        ENV_EXEC,
                        IP6TABLES_EXEC,
                        "--list",
                        self.chain,
                        "-n",
                        "--line-numbers",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()
                    assert proc.returncode == 0, stderr
                    out = stdout
                except AssertionError as err:
                    if "you must be root" in str(err):
                        print(
                            "Looks like blocky doesn't have permission to access ip6tables, giving up completely! (are you "
                            "running as root?)"
                        )
                        sys.exit(-1)
                    if "No chain/target/match" in str(err):
                        continue
                    await asyncio.sleep(1)  # write lock, probably
                if out:
                    for line in out.decode("ascii").split("\n"):
                        # Unlike ipv4 iptables, the 'option' thing is blank here, so omit it
                        m = re.match(r"^(\d+)\s+([-0-9a-zA-Z]+)\s+(all|tcp|udp)\s+([0-9a-f.:/]+)\s+([0-9a-f.:/]+)\s*(.*?)$", line)
                        if m:
                            line_number = m.group(1)
                            action = m.group(2)
                            protocol = m.group(3)
                            source = m.group(4)
                            destination = m.group(5)
                            extensions = m.group(6)
                            if action and action not in ["DROP", "REJECT"]:   # We only want drops and rejects
                                continue
                            entry = Entry(
                                self.chain, line_number, action, protocol, None, source, destination, extensions
                            )

                            chain_list.append(entry)
                    break
        self.items = chain_list

    async def add(self, ip, reason="No reason given"):
        """Bans an IP or CIDR block generically"""
        rv = await iptables(self, ip, "-A", message=reason)
        if rv:
            return True
        return False

    async def remove(self, ip):
        """Unbans an IP or net block"""
        entry = self.is_blocked(ip)
        if entry:
            print(f"Removing entry {entry.source} from line {entry.line_number} in {self.chain}")
            await self.unban_line(entry.line_number, protocol=entry.as_net.version)
            await self.refresh()  # Line numbers will now have changed, refresh the chain
            return True
        return False

    async def unban_line(self, linenumber, protocol=4):
        """Unbans an IP or block by line number"""
        if not linenumber:
            return
        exe = IPTABLES_EXEC
        if protocol == 6:
            exe = IP6TABLES_EXEC
        try:
            proc = await asyncio.subprocess.create_subprocess_exec(
                ENV_EXEC,
                exe,
                "-D",
                self.chain,
                linenumber,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            assert proc.returncode == 0, stderr
        except AssertionError as err:  # iptables error, expected result variant
            return False
        return True

    def is_blocked(self, ip: typing.Union[Entry, str, netaddr.IPNetwork]) -> typing.Optional[Entry]:
        """Finds out if an IP address or block is contained within a block in this chain. Returns the matching block
        rule if any"""
        if isinstance(ip, Entry):
            if ip in self.items:
                return ip
            return
        if isinstance(ip, str):
            ip = netaddr.IPNetwork(ip)
        for entry in self.items:
            # Either the block is contained within a rule, or the rule is contained within the block...who knows!
            if ip in entry.as_net or entry.as_net in ip:
                return entry


async def iptables(chain, ip, action, message="Blocked by Blocky/4"):
    """Runs an iptables action on an IP (-A, -C or -D), returns true if
    succeeded, false otherwise"""
    try:
        exe = IPTABLES_EXEC
        if ":" in ip:
            exe = IP6TABLES_EXEC
        proc = await asyncio.subprocess.create_subprocess_exec(
            ENV_EXEC,
            exe,
            action,
            chain.chain,
            "-s",
            ip,
            "-j",
            "DROP",
            "-m",
            "comment",
            "--comment",
            message,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        assert proc.returncode == 0, "Could not run iptables!!: %s" % stderr
    except AssertionError as err:  # iptables error, expected result variant
        print(err)
        return False
    return True

# Tests go below:


async def test():
    """Test! fetch all entries in INPUT chain and print them"""
    my_chain = Chain("INPUT")
    await my_chain.refresh()
    for entry in my_chain.items:
        print(entry)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(test())
