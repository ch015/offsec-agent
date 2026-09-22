import { randomUUID } from 'node:crypto';
import { chmodSync, closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';

/** Managed paths must never traverse a link, including the configured root. */
export function managedPath(root: string, path: string): string {
  root = resolve(root); path = resolve(path);
  const rel = relative(root, path);
  if (rel === '..' || rel.startsWith(`..${sep}`)) throw new Error(`storage path escapes root: ${path}`);
  let current = path;
  while (true) {
    if (existsSync(current) || (() => { try { lstatSync(current); return true; } catch { return false; } })()) {
      if (lstatSync(current).isSymbolicLink() && !(process.platform === 'darwin' && ['/tmp', '/var', '/etc'].includes(current))) throw new Error(`storage symlink is forbidden: ${current}`);
    }
    const parent = dirname(current);
    // macOS /tmp and /var are system aliases. Callers canonicalize their root's parent.
    if (parent === current) break;
    current = parent;
  }
  return path;
}

export function privateDirectory(path: string): void {
  managedPath(path, path);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const info = lstatSync(path);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`unsafe storage directory: ${path}`);
  if (process.getuid && info.uid !== process.getuid()) throw new Error(`storage directory belongs to another user: ${path}`);
  chmodSync(path, 0o700);
}

export function atomicPrivateWrite(path: string, content: string | Uint8Array): void {
  managedPath(dirname(path), path);
  privateDirectory(dirname(path));
  const temporary = `${path}.${randomUUID()}.tmp`;
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, content); fsyncSync(fd); } finally { closeSync(fd); }
  try { renameSync(temporary, path); } finally { if (existsSync(temporary)) unlinkSync(temporary); }
}

export function readManagedFile(root: string, path: string): Buffer {
  path = managedPath(root, path);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { return readFileSync(fd); } finally { closeSync(fd); }
}
