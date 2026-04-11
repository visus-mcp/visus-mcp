export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  maxWorkers: 1,
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: './tsconfig.test.json',
      },
    ],
  },
  testMatch: ['**/tests/**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  transformIgnorePatterns: [
    'node_modules/(?!(@mozilla/readability|jsdom|@exodus/bytes|html-encoding-sniffer|@toon-format)/)',
  ],
  testTimeout: 15000,
  forceExit: true,
  detectOpenHandles: false,
  collectCoverageFrom: ['src/**/*.ts', '!src/**/__mocks__/**'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
};
