// bundle everything under bundle.js
var rollup = require('rollup');
var babel = require('rollup-plugin-babel');

rollup.rollup({
  entry: 'src/daga.js',
  external: ['protobufjs'],//, 'topl'],
  plugins: [
    babel({
      babelrc: false,
      presets: [["es2015-rollup"]]
    })
  ]
}).then(
  (bundle) => {
    console.log('write file');

    bundle.write({
      format: 'amd',
      moduleName: 'DagaProtobuf',
      dest: 'bundle.js'
    });
  },
  (e) => console.log('error', e)
);
