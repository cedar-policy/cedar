# cedar-wasm

An implementation of various cedar functions to enable developers to write typescript and javascript applications using Cedar and wasm.

## Installing

Installing is simple, just run `npm i @cedar-policy/cedar-wasm --save` or install with whatever your favorite package manager is.

Loading is much more complicated. It depends on your environment. We offer three subpackages:

* es modules (default). It loads wasm in a way that will be bundled into a single file if you use dynamic imports, or embedded into your main bundle if you use regular imports.
* commonjs (for node). It loads wasm using node's `fs` module, synchronously. Not really designed for bundling or shipping to the browser.
* web: more customizable. This one is for when you need to load the wasm in some totally custom way. More details in the "alternate loading strategies" section.

These sub-packages are named `@cedar-policy/cedar-wasm`, `@cedar-policy/cedar-wasm/nodejs`, and `@cedar-policy/cedar-wasm/web`, respectively.

## Loading in bare nodeJs without a bundler

Node uses CommonJs so you have to import with require, or with dynamic `import()`. 

Importing the CJS export:

```
const cedar = require('@cedar-policy/cedar-wasm/nodejs');
console.log(cedar.getCedarVersion());
```

Importing the esm version using esm async import:

```
import('@cedar-policy/cedar-wasm/nodejs')
  .then(cedar => console.log(cedar.getCedarVersion()));
```


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
    "webpack-dev-server": "^5.0.4",
    "html-webpack-plugin": "^5.6.0"
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
const HtmlWebpackPlugin = require('html-webpack-plugin');

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
  plugins: [new HtmlWebpackPlugin()],
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

If for some reason you cannot use es modules, we provide alternate sub-packages `web` and `nodejs` (defined as `exports` in the root package.json).

The `nodejs` subpackage uses `fs` and CommonJS modules. To use it, you can import it like so:

```
const cedar = require('@cedar-policy/cedar-wasm/nodejs')
```

The `web` subpackage exposes an `initSync` function that you can use to load Cedar in scenarios where you want to load the wasm binary async for whatever reason. Using the `web` subpackage may also be necessary with some `jest` setups. Here's how you use the `web` subpackage:

```
const wasmBuffer = ... // `fetch` it or use `fs` to read it from `node_modules` in jest setupTests
import * as cedarJsBindings from '@cedar-policy/cedar-wasm/web';
cedarJsBindings.initSync(wasmBuffer);
```
