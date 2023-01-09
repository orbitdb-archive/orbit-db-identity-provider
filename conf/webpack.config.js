import path from 'path'
import webpack from 'webpack'
import { fileURLToPath } from 'url'

export default (env, argv) => {
  const __filename = fileURLToPath(import.meta.url)
  const __dirname = path.dirname(__filename)

  return {
    mode: 'production',
    entry: './src/identities.js',
    output: {
      libraryTarget: 'var',
      library: 'Identities',
      filename: '../dist/orbit-db-identity-provider.min.js'
    },
    target: 'web',
    devtool: 'source-map',
    plugins: [
      new webpack.DefinePlugin({
        'process.env.NODE_ENV': JSON.stringify('production')
      })
    ],
    resolve: {
      modules: [
        'node_modules'
      ],
      alias: {
        leveldown: 'level-js'
      },
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
      ],
      extensions: ['.js', '.json'],
      mainFields: ['loader', 'main']
    }
  }
}
