# cedar-wasm

An implementation of various cedar functions to enable developers to write typescript and javascript applications using Cedar and wasm.

## Installing

Installing is simple, just run `npm i @cedar-policy/cedar-wasm --save` or install with whatever your favorite package manager is.

## Loading in webpack 5:

Minimal package.json for webpack including dev server:

```
{
  "name": "webpack-ts-tester",
  "version": "1.0.0",
  "description": "", 
  "private": true,
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "build": "webpack",
    "dev": "webpack serve"
  },  
  "keywords": [], 
  "author": "", 
  "license": "ISC",
  "dependencies": {
    "@cedar-policy/cedar-wasm": "3.2.0"
  },  
  "devDependencies": {
    "ts-loader": "^9.5.1",
    "typescript": "^5.4.5",
    "webpack": "^5.91.0",
    "webpack-cli": "^5.1.4",
    "webpack-dev-server": "^5.0.4"
  }
}
```

Minimal tsconfig:

```
{
  "compilerOptions": {
    "outDir": "./dist/",
    "noImplicitAny": true,
    "module": "es2020",
    "target": "es5",
    "jsx": "react",
    "allowJs": true,
    "moduleResolution": "node"
  }
}
```

Configure webpack.config.js:

```
const path = require('path');

module.exports = { 
  mode: 'development', // change this to suit you
  entry: './src/index.ts',
  module: {
    rules: [
      {   
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },  
    ],  
  },  
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
  },  
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
  },  
  experiments: {
    asyncWebAssembly: true, // enables wasm support in webpack
  },  
  devServer: {
    static: {
      directory: path.join(__dirname, 'dist'),
    },  
    compress: true,
    port: 8000,
  }
};
```

Finally, load the code from your `index.ts` file. We recommend dynamic imports:

```
import('@cedar-policy/cedar-wasm').then(mod => {
  // cache it globally here or invoke functions like mod.getCedarVersion();
});
```



## Loading in vite 5:

Starting from the vite typescript template, install these two dependencies to enable wasm:

```
npm i --save-dev vite-plugin-top-level-await vite-plugin-wasm
```

Then add those two plugins to your vite config in `vite.config.js`:

```
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
    wasm(),
    topLevelAwait()
  ]
});

```

Finally, load the code. We recommend dynamic imports:

```
import('@cedar-policy/cedar-wasm').then(mod => {
  // cache it globally here or invoke functions like mod.getCedarVersion();
});
```

## Alternate loading strategies

If for some reason you cannot use es modules, we provide alternate sub-packages `web` and `node`.

The `node` subpackage uses `fs` and CommonJS modules. To use it, you can import it like so:

```
const cedar = require('@cedar-policy/cedar-wasm/node')
```

The `web` subpackage exposes an `initSync` function that you can use to load Cedar in scenarios where you want to load the wasm binary async for whatever reason. Using the `web` subpackage may also be necessary with some `jest` setups. Here's how you use the `web` subpackage:

```
const wasmBuffer = ... // `fetch` it or use `fs` to read it from `node_modules` in jest setupTests
import * as cedarJsBindings from '@cedar-policy/cedar-wasm/web';
cedarJsBindings.initSync(wasmBuffer);
```
