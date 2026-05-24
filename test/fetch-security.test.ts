import assert from "node:assert/strict";
import test from "node:test";
import {
  isBlockedHostname,
  isBlockedResolvedAddress,
  isConfiguredFakeIpAddress,
  isPrivateAddress,
  resolveSafeAddresses,
  setDnsLookupForTests,
  type DnsLookup
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

async function withFakeIpCidrsAsync<T>(
  value: string | undefined,
  run: () => Promise<T>
): Promise<T> {
  const previous = process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS;
  if (value === undefined) {
    delete process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS;
  } else {
    process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS = value;
  }

  try {
    return await run();
  } finally {
    if (previous === undefined) {
      delete process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS;
    } else {
      process.env.FETCH_URL_ALLOWED_FAKE_IP_CIDRS = previous;
    }
  }
}

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

test("fake-IP DNS answers are blocked unless explicitly configured", () => {
  assert.equal(isPrivateAddress("198.18.0.130"), true);
  withFakeIpCidrs(undefined, () => {
    assert.equal(isConfiguredFakeIpAddress("198.18.0.130"), false);
    assert.equal(isBlockedResolvedAddress("198.18.0.130"), true);
  });
});

test("configured fake-IP CIDRs can be allowed for resolved public hostnames", () => {
  withFakeIpCidrs("198.18.0.0/15", () => {
    assert.equal(isConfiguredFakeIpAddress("198.18.0.130"), true);
    assert.equal(isBlockedResolvedAddress("198.18.0.130"), false);
    assert.equal(isConfiguredFakeIpAddress("::ffff:198.18.0.130"), true);
    assert.equal(isBlockedResolvedAddress("::ffff:198.18.0.130"), false);
    assert.equal(isConfiguredFakeIpAddress("::ffff:c612:0082"), true);
    assert.equal(isBlockedResolvedAddress("::ffff:c612:0082"), false);
    assert.equal(isConfiguredFakeIpAddress("0:0:0:0:0:ffff:c612:82"), true);
    assert.equal(isBlockedResolvedAddress("0:0:0:0:0:ffff:c612:82"), false);
  });
});

test("malformed and sensitive fake-IP CIDR entries fail closed", () => {
  for (const value of [
    "198.18.0.0/",
    "198.18.0.0//15",
    "198.18.0.0/not-a-prefix",
    "198.18.0.0/-1",
    "198.18.0.0/33",
    "0.0.0.0/0",
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "224.0.0.0/4",
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

test("fake-IP compatibility only applies to IPv4 and true IPv4-mapped IPv6", () => {
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
  assert.equal(isBlockedHostname("198.18.0.130"), true);
});

test("resolved private IPv4-mapped IPv6 loopback remains blocked", () => {
  assert.equal(isBlockedResolvedAddress("0:0:0:0:0:ffff:7f00:1"), true);
  assert.equal(isBlockedResolvedAddress("0:0:0:0:0:ffff:0a00:1"), true);
});

test("resolveSafeAddresses blocks fake-IP DNS when unset", async () => {
  withFakeIpCidrs(undefined, () => {
    assert.equal(isConfiguredFakeIpAddress("198.18.0.130"), false);
  });

  await withResolver(
    async () => [{ address: "198.18.0.130" }],
    async () => {
      await assert.rejects(
        () => resolveSafeAddresses("example.com"),
        /Blocked localhost\/private URL/
      );
    }
  );
});

test("resolveSafeAddresses handles configured fake-IP DNS deterministically", async () => {
  await withResolver(
    async () => [{ address: "198.18.0.130" }],
    async () => {
      await withFakeIpCidrsAsync("198.18.0.0/15", async () => {
        assert.equal(isConfiguredFakeIpAddress("198.18.0.130"), true);
        assert.deepEqual(await resolveSafeAddresses("example.com"), ["198.18.0.130"]);
      });
    }
  );
});

test("resolveSafeAddresses rejects mixed fake-IP and true private DNS results", async () => {
  await withResolver(
    async () => [{ address: "198.18.0.130" }, { address: "10.0.0.1" }],
    async () => {
      await withFakeIpCidrsAsync("198.18.0.0/15", async () => {
        await assert.rejects(
          () => resolveSafeAddresses("example.com"),
          /Blocked localhost\/private URL/
        );
      });
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
