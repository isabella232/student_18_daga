// bundle everything in
var rollup = require('rollup');
var babel = require('rollup-plugin-babel');

rollup.rollup({
  entry: 'src/daga.js',
  external: ['protobufjs'],
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
      format: 'iife',
      moduleName: 'DagaProtobuf',
      dest: 'js/bundle.js'
    });
  },
  (e) => console.log('error', e)
);
