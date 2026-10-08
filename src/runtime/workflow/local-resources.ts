import { freemem, platform } from 'node:os';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

/** Free pages alone exclude reclaimable cache on macOS/Linux. Sample at most every 5s. */
export function localResourceCapacity(): () => number {
  let sampledAt = -Infinity, bytes = 0;
  return () => {
    if (Date.now() - sampledAt >= 5000) {
      sampledAt = Date.now(); bytes = freemem();
      try {
        if (platform() === 'linux') {
          const available = /^MemAvailable:\s+(\d+) kB$/m.exec(readFileSync('/proc/meminfo', 'utf8'));
          if (available) bytes = Number(available[1]) * 1024;
        } else if (platform() === 'darwin') {
          const stats = execFileSync('/usr/bin/vm_stat', { encoding: 'utf8', timeout: 500 });
          const size = Number(/page size of (\d+)/.exec(stats)?.[1]);
          const pages = ['free', 'inactive', 'speculative'].map(name => Number(new RegExp(`Pages ${name}:\\s+(\\d+)`).exec(stats)?.[1] ?? 0));
          if (size > 0) bytes = pages.reduce((sum, count) => sum + count, 0) * size;
        }
      } catch { /* Unknown reclaimable memory: retain the conservative OS free-page reading. */ }
    }
    return Math.max(0, Math.floor(bytes / (128 * 1024 * 1024)));
  };
}
