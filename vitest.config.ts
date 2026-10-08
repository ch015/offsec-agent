import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Integration fixtures fsync many artifacts and spawn provider test processes.
    // Bound parallel files instead of masking contention by raising test timeouts.
    maxWorkers: 2,
    minWorkers: 1,
    include: ['src/**/__tests__/**/*.test.ts', 'evals/**/*.test.ts'],
  },
});
