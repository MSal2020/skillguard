import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Only our own tests — never the cloned benchmark corpus under bench/.corpus.
    include: ['test/**/*.test.ts'],
  },
});
