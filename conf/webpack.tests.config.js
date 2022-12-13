import glob from 'glob'
import webpack from 'webpack'
import { createRequire } from 'module'

export default (env, argv) => {
  const require = createRequire(import.meta.url)
  return {
    // TODO: put all tests in a .js file that webpack can use as entry point
    entry: glob.sync('./test/*.spec.js'),
    output: {
      filename: '../test/browser/bundle.js'
    },
    target: 'web',
    mode: 'production',
    devtool: 'source-map',
    plugins: [
      new webpack.ProvidePlugin({
        process: 'process/browser',
        Buffer: ['buffer', 'Buffer']
      })
    ],
    externals: {
      bindings: '{}',
      leveldown: '{}',
      fs: '{}',
      fatfs: '{}',
      runtimejs: '{}',
      rimraf: '{ sync: () => {} }',
      'graceful-fs': '{}',
      'fs-extra': '{ copy: () => {} }',
      'fs.realpath': '{}'
      // dns: '{}',
      // "node-gyp-build": '{}'
    },
    experiments: {
      topLevelAwait: true
    },
    resolve: {
      modules: [
        'node_modules'
      ],
      fallback: {
        buffer: require.resolve('buffer/'),
        events: require.resolve('events/'),
        assert: require.resolve('assert'),
        path: require.resolve('path-browserify'),
        stream: require.resolve('stream-browserify')
      }
    },
    module: {
      rules: [
        {
          test: /\.m?js$/,
          exclude: /node_modules/,
          use: {
            loader: 'babel-loader',
            options: {
              presets: ['@babel/preset-env'],
              plugins: ['@babel/plugin-syntax-import-assertions']
            }
          }
        }
      ]
    }
  }
}
