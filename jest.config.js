module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  moduleNameMapper: {
    // Allow TypeScript ESM-style imports with .js extension to resolve to .ts files
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
};
