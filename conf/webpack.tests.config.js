'use strict'

const glob = require('glob')
const webpack = require('webpack')
const path = require('path')

module.exports = {
  // TODO: put all tests in a .js file that webpack can use as entry point
  entry: glob.sync('./test/*.spec.js'),
  output: {
    filename: '../test/browser/bundle.js'
  },
  target: 'web',
  devtool: 'source-map',
  node: {
    child_process: 'empty'
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env': {
        NODE_ENV: JSON.stringify(process.env.NODE_ENV)
      }
    }),
    new webpack.IgnorePlugin(/mongo|redis/)
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
  resolve: {
    modules: [
      'node_modules',
      path.resolve(__dirname, '../node_modules')
    ]
  },
  resolveLoader: {
    modules: [
      'node_modules',
      path.resolve(__dirname, '../node_modules')
    ],
    moduleExtensions: ['-loader']
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', { modules: false }]
            ],
            plugins: ['@babel/syntax-object-rest-spread', '@babel/transform-runtime', '@babel/plugin-transform-modules-commonjs']
          }
        }
      },
      {
        test: /existing|QmPhnEjVkYE1Ym7F5MkRUfkD6NtuSptE7ugu1Ggr149W2X|0260baeaffa1de1e4135e5b395e0380563a622b9599d1b8e012a0f7603f516bdaa$/,
        loader: 'json-loader'
      }
    ]
  }
}
