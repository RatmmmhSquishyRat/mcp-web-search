import assert from "node:assert/strict";
import test from "node:test";
import {
  isBlockedHostname,
  isBlockedResolvedAddress,
  isKnownFakeIpAddress,
  isPrivateAddress,
  resolveSafeAddresses,
  setDnsLookupForTests,
  type DnsLookup
} from "../src/fetch/security.js";

async function withResolver<T>(resolver: DnsLookup, run: () => Promise<T>): Promise<T> {
  setDnsLookupForTests(resolver);
  try {
    return await run();
  } finally {
    setDnsLookupForTests(null);
  }
}

test("isPrivateAddress blocks IPv4-mapped IPv6 private addresses", () => {
  assert.equal(isPrivateAddress("::ffff:127.0.0.1"), true);
  assert.equal(isPrivateAddress("::ffff:7f00:1"), true);
  assert.equal(isPrivateAddress("0:0:0:0:0:ffff:7f00:1"), true);
  assert.equal(isPrivateAddress("0:0:0:0:0:ffff:0a00:1"), true);
  assert.equal(isPrivateAddress("0:0:0:0:0:ffff:c0a8:101"), true);
  assert.equal(isPrivateAddress("::ffff:192.168.1.1"), true);
});

test("isPrivateAddress blocks full IPv6 link-local and multicast ranges", () => {
  assert.equal(isPrivateAddress("fe80::1"), true);
  assert.equal(isPrivateAddress("fe90::1"), true);
  assert.equal(isPrivateAddress("febf::1"), true);
  assert.equal(isPrivateAddress("ff02::1"), true);
});

test("isPrivateAddress allows ordinary public IPv6 addresses", () => {
  assert.equal(isPrivateAddress("2606:4700:4700::1111"), false);
});

test("known fake-IP DNS answers are allowed for resolved public hostnames", () => {
  assert.equal(isPrivateAddress("198.18.0.130"), true);
  assert.equal(isKnownFakeIpAddress("198.18.0.130"), true);
  assert.equal(isBlockedResolvedAddress("198.18.0.130"), false);
  assert.equal(isKnownFakeIpAddress("::ffff:198.18.0.130"), true);
  assert.equal(isBlockedResolvedAddress("::ffff:198.18.0.130"), false);
  assert.equal(isKnownFakeIpAddress("::ffff:c612:0082"), true);
  assert.equal(isBlockedResolvedAddress("::ffff:c612:0082"), false);
  assert.equal(isKnownFakeIpAddress("0:0:0:0:0:ffff:c612:82"), true);
  assert.equal(isBlockedResolvedAddress("0:0:0:0:0:ffff:c612:82"), false);
});

test("fake-IP compatibility only applies to IPv4 and true IPv4-mapped IPv6", () => {
  assert.equal(isKnownFakeIpAddress("fc00::198.18.0.130"), false);
  assert.equal(isKnownFakeIpAddress("fe80::198.18.0.130"), false);
  assert.equal(isKnownFakeIpAddress("ff02::198.18.0.130"), false);
  assert.equal(isBlockedResolvedAddress("fc00::198.18.0.130"), true);
  assert.equal(isBlockedResolvedAddress("fe80::198.18.0.130"), true);
  assert.equal(isBlockedResolvedAddress("ff02::198.18.0.130"), true);
});

test("direct fake-IP URLs remain blocked even when resolved fake IPs are allowed", () => {
  assert.equal(isBlockedHostname("198.18.0.130"), true);
});

test("resolved private IPv4-mapped IPv6 loopback remains blocked", () => {
  assert.equal(isBlockedResolvedAddress("0:0:0:0:0:ffff:7f00:1"), true);
  assert.equal(isBlockedResolvedAddress("0:0:0:0:0:ffff:0a00:1"), true);
});

test("resolveSafeAddresses handles fake-IP DNS deterministically", async () => {
  await withResolver(
    async () => [{ address: "198.18.0.130" }],
    async () => {
      assert.deepEqual(await resolveSafeAddresses("example.com"), ["198.18.0.130"]);
    }
  );
});

test("resolveSafeAddresses rejects true private DNS results deterministically", async () => {
  await withResolver(
    async () => [{ address: "10.0.0.1" }],
    async () => {
      await assert.rejects(
        () => resolveSafeAddresses("example.com"),
        /Blocked localhost\/private URL/
      );
    }
  );
});
