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
"""Blocky4 client application"""
import netaddr
import time
import iptables
import asyncio
import yaml
import asfpy.syslog
import asfpy.whoami
import aiohttp
import json

MAX_BLOCK_SIZE_IPV4 = (2 ** 16)  # Max a /16 block in IPv4 space (32 - 16 == /16)
MAX_BLOCK_SIZE_IPV6 = (2 ** 72)  # Max a /56 block in IPv6 space (128 - 72 == /56)


# Redirect print to asfpy's syslog printer, duplicate to stdout
print = asfpy.syslog.Printer(stdout=True, identity="blocky")


async def upload_iptables(config, chains):
    # Turn all rules in all chains into dicts, add to a big list
    rules_as_dict = []
    for chain in chains:
        await chain.refresh()
        for rule in chain.items:
            rules_as_dict.append(rule.to_dict())
    #  print("Uploading iptables list (%u entries) to Blocky server" % len(rules_as_dict))
    try:
        js = {"hostname": config["whoami"], "iptables": rules_as_dict}
        timeout = aiohttp.ClientTimeout(total=15)
        api_url = "%s/upload" % config["api_host"]
        async with aiohttp.request("PUT", api_url, json=js, timeout=timeout) as resp:
            response = await resp.json()
            assert resp.status == 200, f"{resp.status}: {resp.reason}"
            #  print(response)
    except AssertionError as status:
        print(f"Server responded with code {status}")
    except aiohttp.ClientConnectorError as e:
        print("Could not send my iptables list to server at %s - server down or wrong URL?" % api_url)
    except aiohttp.ClientTimeout as e:
        print("Could not send my iptables list to server at %s - server response timed out" % api_url)


def find_block(chains, ip):
    """Find out if an IP matches any rule in any chain we have"""
    for chain in chains:
        rule = chain.is_blocked(ip)
        if rule:
            return rule, chain
    return None, None


async def process_changes(config, chains, allow=[], block=[]):
    """Process allows and blocks"""
    allow_blocks = []
    if allow or block:
        print("Processing upstream change-set (%u entries)" % (len(allow) + len(block)))
    processed = 0
    # First process any new allows
    if allow and chains:  # If we have an INPUT default chain, refresh before unblock.
        await chains[0].refresh()

    for entry in allow:
        ip = entry["ip"]
        if ip:
            if "/" in ip:
                as_block = netaddr.IPNetwork(ip)
            else:
                if ":" in ip:
                    as_block = netaddr.IPNetwork("%s/128" % ip)  # IPv6
                else:
                    as_block = netaddr.IPNetwork("%s/32" % ip)  # IPv4
            allow_blocks.append(as_block)
            rule, chain = find_block(chains, as_block)
            while rule:
                print("Removing %s from block list (found at line %s as %s)" % (ip, rule.line_number, rule.source))
                rv = await chain.remove(rule)
                if not rv:
                    print("Could not remove ban for %s from iptables!" % ip)
                else:
                    rule, chain = find_block(chains, as_block)

    # Then process blocks
    for entry in block:
        ip = entry["ip"]
        if ip:
            processed += 1
            if (processed % 500) == 0:
                print("Processed %u entries..." % processed)
            # Only apply blocks if host is * or our specific name
            if entry.get('host', '*') not in [config['whoami'], '*']:
                continue
            banit = True
            if "/" in ip:
                as_block = netaddr.IPNetwork(ip)
                # We never ban larger than a /8 on ipv4 and /56 on ipv6
                if (as_block.version == 4 and as_block.size > MAX_BLOCK_SIZE_IPV4) or (
                    as_block.version == 6 and as_block.size > MAX_BLOCK_SIZE_IPV6
                ):
                    print("%s was requested banned but the net block is too large (%u IPs)" % (as_block, as_block.size))
                    continue
            else:
                if ":" in ip:
                    as_block = netaddr.IPNetwork("%s/128" % ip)  # IPv6
                else:
                    as_block = netaddr.IPNetwork("%s/32" % ip)  # IPv4
            for wblock in allow_blocks:
                if as_block in wblock or wblock in as_block:
                    print("%s was requested banned but %s is allow-listed, ignoring ban" % (as_block, wblock))
                    banit = False
            if banit:
                rule, chain = find_block(chains, as_block)
                if not rule:
                    print("Adding %s to block list" % ip)
                    rv = await chains[0].add(ip, reason=entry["reason"])
                    if not rv:
                        print("Could not add ban for %s in iptables!" % ip)


async def loop(config):
    uri = config["api_host"]

    # Get current list of bans in iptables, upload it to blocky server
    chains_to_check = config.get("chains") or ["INPUT"]
    chains = []
    for chain_name in chains_to_check:
        chain = iptables.Chain(chain_name)
        await chain.refresh()
        chains.append(chain)

    last_upload = 0

    while True:
        async with aiohttp.ClientSession() as session:
            try:
                rv = await session.get(f"{uri}/all")
                assert rv.status == 200, f"API host responded with bad status: {rv.status}"
                js = await rv.json()
                await process_changes(config, chains, allow=js["allow"], block=js["block"])

                # Attach to pubsub and listen for new blocks/allows
                async with session.get(config["pubsub_host"], timeout=None) as pubsub_conn:
                    buffer = b""
                    async for data, end_of_http_chunk in pubsub_conn.content.iter_chunks():
                        buffer += data
                        if end_of_http_chunk:
                            chunk = buffer.decode("utf-8").strip()
                            buffer = b""
                            if chunk:
                                try:
                                    payload = json.loads(chunk)
                                    if "blocky" in payload.get("pubsub_topics", []):
                                        if "block" in payload:
                                            await process_changes(config, chains, block=[payload["block"]])
                                        elif "allow" in payload:
                                            await process_changes(config, chains, allow=[payload["allow"]])
                                except json.JSONDecodeError as e:
                                    print(e)
                        if last_upload + config.get("upload_interval", 300) < time.time():
                            await upload_iptables(config, chains)
                            last_upload = time.time()
            except Exception as e:
                print("[%u] Connection failed (%s: %s), reconnecting in 30 seconds" % (time.time(), type(e), e))
                await asyncio.sleep(30)


def main():
    # Load YAML
    config = yaml.safe_load(open("blocky.yaml").read())
    if "whoami" not in config:
        config["whoami"] = asfpy.whoami.whoami()
    config["api_host"] = config["api_host"].rstrip("/")
    # Start async loop
    asyncio.get_event_loop().run_until_complete(loop(config))


if __name__ == "__main__":
    main()
