'use strict'

const path = require('path')

module.exports = {
  entry: './src/purser-metamask-identity-provider.js',
  output: {
    libraryTarget: 'var',
    library: 'MetamaskIdentityProvider',
    filename: 'metamask-ip.min.js'
  },
  target: 'web',
  devtool: 'sourcemap',
  node: {
    console: false,
    Buffer: true
  },
  plugins: [
  ],
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
  }
}
