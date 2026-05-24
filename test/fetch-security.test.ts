import assert from "node:assert/strict";
import test from "node:test";
import {
  isBlockedHostname,
  isBlockedResolvedAddress,
  isConfiguredFakeIpAddress,
  isPrivateAddress
} from "../src/fetch/security.js";

function withFakeIpCidrs(value: string | undefined, run: () => void) {
  const previous = process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS;
  if (value === undefined) {
    delete process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS;
  } else {
    process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS = value;
  }

  try {
    run();
  } finally {
    if (previous === undefined) {
      delete process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS;
    } else {
      process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS = previous;
    }
  }
}

test("isPrivateAddress blocks IPv4-mapped IPv6 private addresses", () => {
  assert.equal(isPrivateAddress("::ffff:127.0.0.1"), true);
  assert.equal(isPrivateAddress("::ffff:7f00:1"), true);
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

test("configured fake-IP CIDRs can be allowed for resolved public hostnames", () => {
  withFakeIpCidrs("198.18.0.0/15", () => {
    assert.equal(isPrivateAddress("198.18.0.130"), true);
    assert.equal(isConfiguredFakeIpAddress("198.18.0.130"), true);
    assert.equal(isBlockedResolvedAddress("198.18.0.130"), false);
    assert.equal(isConfiguredFakeIpAddress("::ffff:198.18.0.130"), true);
    assert.equal(isBlockedResolvedAddress("::ffff:198.18.0.130"), false);
    assert.equal(isConfiguredFakeIpAddress("::ffff:c612:0082"), true);
    assert.equal(isBlockedResolvedAddress("::ffff:c612:0082"), false);
  });
});

test("malformed fake-IP CIDR entries fail closed", () => {
  for (const value of [
    "198.18.0.0/",
    "198.18.0.0//15",
    "198.18.0.0/not-a-prefix",
    "198.18.0.0/-1",
    "198.18.0.0/33",
    "0.0.0.0/0",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "198.18.0.0/14"
  ]) {
    withFakeIpCidrs(value, () => {
      assert.equal(isConfiguredFakeIpAddress("198.18.0.130"), false, value);
      assert.equal(isBlockedResolvedAddress("198.18.0.130"), true, value);
      assert.equal(isBlockedResolvedAddress("127.0.0.1"), true, value);
      assert.equal(isBlockedResolvedAddress("10.0.0.1"), true, value);
    });
  }
});

test("fake-IP allowlist only applies to IPv4 and true IPv4-mapped IPv6", () => {
  withFakeIpCidrs("198.18.0.0/15", () => {
    assert.equal(isConfiguredFakeIpAddress("fc00::198.18.0.130"), false);
    assert.equal(isConfiguredFakeIpAddress("fe80::198.18.0.130"), false);
    assert.equal(isConfiguredFakeIpAddress("ff02::198.18.0.130"), false);
    assert.equal(isBlockedResolvedAddress("fc00::198.18.0.130"), true);
    assert.equal(isBlockedResolvedAddress("fe80::198.18.0.130"), true);
    assert.equal(isBlockedResolvedAddress("ff02::198.18.0.130"), true);
  });
});

test("direct fake-IP URLs remain blocked even when resolved fake IPs are allowed", () => {
  withFakeIpCidrs("198.18.0.0/15", () => {
    assert.equal(isBlockedHostname("198.18.0.130"), true);
  });
});
