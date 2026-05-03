export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      useESM: true,
      tsconfig: 'tsconfig.test.json'
    }],
  },
  transformIgnorePatterns: [
    '/node_modules/(?!(@exodus/bytes|jsdom|playwright-core)/)',
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/jest-setup.ts'],
};
