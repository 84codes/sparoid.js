export default {
  input: 'src/sparoid.mjs',
  external: ['dgram', 'dns', 'crypto', 'buffer', 'process', 'net'],
  output: {
    file: 'dist/sparoid.cjs',
    format: 'cjs',
  }
};
