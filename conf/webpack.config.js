import path from 'path'
import webpack from 'webpack'
import { fileURLToPath } from 'url'
import { createRequire } from 'module'

export default (env, argv) => {
  const require = createRequire(import.meta.url)
  const __filename = fileURLToPath(import.meta.url)
  const __dirname = path.dirname(__filename)

  return {
    mode: 'production',
    entry: './src/identities.js',
    output: {
      filename: '../dist/orbit-db-identity-provider.min.js',
      library: {
        name: 'Identities',
        type: 'var',
        export: 'default'
      }
    },
    target: 'web',
    devtool: 'source-map',
    plugins: [
      new webpack.DefinePlugin({
        'process.env.NODE_ENV': JSON.stringify('production')
      }),
      new webpack.ProvidePlugin({
        Buffer: ['buffer', 'Buffer']
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
        stream: require.resolve('stream-browserify'),
        fs: false
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
