export default {
  input: 'dist/sparoid.js',
  external: ['dgram', 'dns', 'crypto', 'buffer', 'process', 'net'],
  output: {
    file: 'dist/sparoid.cjs',
    format: 'cjs',
  }
};
