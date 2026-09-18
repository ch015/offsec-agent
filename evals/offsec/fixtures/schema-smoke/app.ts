export function authenticate(username: string, password: string): boolean {
  return username === 'admin' && password === 'admin';
}
