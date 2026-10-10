/**
 * Server-side request forgery guard for the header-check API: the server must only ever fetch
 * public web pages, never localhost, the LAN or cloud metadata endpoints.
 */

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.intranet', '.lan', '.home.arpa', '.corp'];

/** true for hostnames that name the machine itself or a private network. */
export function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) return true;
  if (host === 'metadata.google.internal' || host === 'metadata') return true;
  const ip = host.startsWith('[') ? host.slice(1, -1) : host;
  if (isIPv4(ip) || ip.includes(':')) return isPrivateAddress(ip);
  return false;
}

function isIPv4(value: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) && value.split('.').every((n) => Number(n) <= 255);
}

/** true for loopback, private, link-local, CGNAT, multicast, reserved and unspecified addresses. */
export function isPrivateAddress(address: string): boolean {
  const ip = address.toLowerCase();
  if (isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number) as [number, number];
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) || // CGNAT
      (a === 169 && b === 254) || // link-local, cloud metadata
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224 // multicast + reserved + broadcast
    );
  }
  if (!ip.includes(':')) return false;
  if (ip === '::' || ip === '::1') return true;
  // IPv4-mapped / translated (::ffff:10.0.0.1 or ::ffff:a00:1)
  const mapped = ip.match(/^::ffff:(?:0:)?(.+)$/);
  if (mapped) {
    const rest = mapped[1]!;
    if (isIPv4(rest)) return isPrivateAddress(rest);
    const hex = rest.split(':');
    if (hex.length === 2) {
      const n = (parseInt(hex[0]!, 16) << 16) | parseInt(hex[1]!, 16);
      return isPrivateAddress([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
    }
    return true;
  }
  const first = parseInt(ip.split(':')[0] || '0', 16);
  return (
    (first & 0xfe00) === 0xfc00 || // fc00::/7 unique local
    (first & 0xffc0) === 0xfe80 || // fe80::/10 link-local
    (first & 0xff00) === 0xff00 || // multicast
    ip.startsWith('64:ff9b:') || // NAT64 can reach private IPv4
    ip.startsWith('2001:db8:') // documentation
  );
}
