import { lookup } from "node:dns/promises";
import net from "node:net";

const BLOCKED_HOSTS = new Set(["localhost", "localhost.localdomain"]);
const FAKE_IP_RANGE_START = ipv4ToNumber([198, 18, 0, 0]);
const FAKE_IP_RANGE_END = ipv4ToNumber([198, 19, 255, 255]);

type LookupRecord = { address: string };
export type DnsLookup = (
  hostname: string,
  options: { all: true; verbatim: true }
) => Promise<LookupRecord[]>;

let dnsLookup: DnsLookup = lookup;

export function setDnsLookupForTests(resolver: DnsLookup | null): void {
  dnsLookup = resolver ?? lookup;
}

function ipv4ToNumber(parts: number[]): number {
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function parseIPv4(address: string): number[] | null {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return parts;
}

function ipv4AddressToNumber(address: string): number | null {
  const parts = parseIPv4(address);
  return parts ? ipv4ToNumber(parts) : null;
}

function isKnownFakeIpV4(address: string): boolean {
  const value = ipv4AddressToNumber(address);
  return value !== null && value >= FAKE_IP_RANGE_START && value <= FAKE_IP_RANGE_END;
}

function parseIPv6Segments(address: string): number[] | null {
  if (net.isIP(address) !== 6) return null;

  const normalized = address.toLowerCase();
  if (normalized.split("::").length > 2) return null;

  const parsePart = (part: string): number[] | null => {
    if (!part) return [];

    const rawSegments = part.split(":");
    const segments: number[] = [];
    for (let index = 0; index < rawSegments.length; index += 1) {
      const segment = rawSegments[index];
      if (!segment) return null;

      if (segment.includes(".")) {
        if (index !== rawSegments.length - 1) return null;
        const ipv4 = parseIPv4(segment);
        if (!ipv4) return null;
        segments.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3]);
        continue;
      }

      if (!/^[0-9a-f]{1,4}$/.test(segment)) return null;
      segments.push(Number.parseInt(segment, 16));
    }
    return segments;
  };

  const [leftText, rightText] = normalized.split("::");
  const left = parsePart(leftText);
  const right = rightText === undefined ? [] : parsePart(rightText);
  if (!left || !right) return null;

  if (rightText === undefined) {
    return left.length === 8 ? left : null;
  }

  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function mappedIPv4(address: string): string | null {
  const segments = parseIPv6Segments(address);
  if (!segments) return null;
  if (!segments.slice(0, 5).every(segment => segment === 0) || segments[5] !== 0xffff) return null;

  const high = segments[6];
  const low = segments[7];
  return `${(high >> 8) & 255}.${high & 255}.${(low >> 8) & 255}.${low & 255}`;
}

function isIPv4Private(address: string): boolean {
  const parts = parseIPv4(address);
  if (!parts) return false;

  const [a, b] = parts;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;
  return false;
}

function fakeIpComparableIPv4(address: string): string | null {
  if (net.isIP(address) === 4) return address;
  return mappedIPv4(address);
}

function firstIPv6Segment(address: string): number | null {
  const segment = address.toLowerCase().split(":", 1)[0];
  if (!segment) return null;
  const value = Number.parseInt(segment, 16);
  return Number.isFinite(value) ? value : null;
}

function isIPv6Private(address: string): boolean {
  const normalized = address.toLowerCase();
  const ipv4 = mappedIPv4(normalized);
  if (ipv4) return isIPv4Private(ipv4);

  const first = firstIPv6Segment(normalized);
  if (normalized === "::1" || normalized === "::") return true;
  if (first === null) return false;
  if ((first & 0xfe00) === 0xfc00) return true;
  if ((first & 0xffc0) === 0xfe80) return true;
  if ((first & 0xff00) === 0xff00) return true;
  return false;
}

export function isPrivateAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 4) return isIPv4Private(address);
  if (family === 6) return isIPv6Private(address);
  return false;
}

export function isKnownFakeIpAddress(address: string): boolean {
  const ipv4 = fakeIpComparableIPv4(address);
  if (!ipv4) return false;
  return isKnownFakeIpV4(ipv4);
}

export function isBlockedHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(lower)) return true;
  if (lower.endsWith(".localhost") || lower.endsWith(".local")) return true;
  if (isPrivateAddress(lower)) return true;
  return false;
}

export function isBlockedResolvedAddress(address: string): boolean {
  return isPrivateAddress(address) && !isKnownFakeIpAddress(address);
}

export async function resolveSafeAddresses(hostname: string): Promise<string[]> {
  if (isBlockedHostname(hostname)) {
    throw new Error("Blocked localhost/private URL");
  }

  try {
    const records = await dnsLookup(hostname, { all: true, verbatim: true });
    const addresses = records.map(record => record.address);
    if (addresses.length === 0 || addresses.some(isBlockedResolvedAddress)) {
      throw new Error("Blocked localhost/private URL");
    }
    return addresses;
  } catch (error) {
    if (error instanceof Error && error.message === "Blocked localhost/private URL") throw error;
    throw new Error(`DNS lookup failed for ${hostname}`);
  }
}

export async function assertSafeUrl(url: URL): Promise<void> {
  if (!/^(https?):$/.test(url.protocol)) {
    throw new Error(`Unsupported URL scheme: ${url.protocol}`);
  }

  await resolveSafeAddresses(url.hostname);
}
