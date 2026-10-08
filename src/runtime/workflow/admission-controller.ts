import { localResourceCapacity } from './local-resources.js';

/** Shared by runs in one host process. Distributed quotas need an external coordinator. */
export class AdmissionController {
  private occupied = 0;
  private pauseUntil = 0;
  constructor(private readonly headroom: () => number = localResourceCapacity()) {}
  available(): number { return Date.now() < this.pauseUntil ? 0 : Math.max(0, Math.floor(this.headroom()) - this.occupied); }
  reserve(): boolean { if (this.available() < 1) return false; this.occupied++; return true; }
  release(): void { if (this.occupied <= 0) throw new Error('Admission occupancy underflow'); this.occupied--; }
  pressure(delayMs: number): void { this.pauseUntil = Math.max(this.pauseUntil, Date.now() + delayMs); }
  snapshot() { return { occupied: this.occupied, pauseUntil: this.pauseUntil }; }
}
export const processAdmissionController = new AdmissionController();
