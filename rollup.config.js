export default {
  input: 'dist/sparoid.js',
  external: ['dgram', 'dns', 'dns/promises', 'crypto', 'buffer', 'process', 'net', 'os'],
  output: {
    file: 'dist/sparoid.cjs',
    format: 'cjs',
  }
};
