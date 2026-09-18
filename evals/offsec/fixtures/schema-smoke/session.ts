export function sessionUser(token: string): string | undefined {
  return token.split('.')[0];
}
