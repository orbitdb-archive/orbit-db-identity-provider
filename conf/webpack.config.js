'use strict'

const path = require('path')

module.exports = {
  entry: './index.js',
  output: {
    libraryTarget: 'var',
    library: 'Identities',
    filename: 'index-browser.min.js'
  },
  target: 'web',
  devtool: 'source-map',
  plugins: [
  ],
  resolve: {
    modules: [
      'node_modules',
      path.resolve(__dirname, '../node_modules')
    ],
    fallback: {
      assert: require.resolve('assert'),
      path: require.resolve('path-browserify'),
      stream: require.resolve('stream-browserify')
    }
  },
  resolveLoader: {
    modules: [
      'node_modules',
      path.resolve(__dirname, '../node_modules')
    ]
  }
}
