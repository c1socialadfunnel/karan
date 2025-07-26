const { getDefaultConfig } = require('expo/metro-config');

/** @type {import('expo/metro-config').MetroConfig} */
const config = getDefaultConfig(__dirname);

// Add support for additional file extensions
config.resolver.assetExts.push(
  // Adds support for `.db` files for SQLite databases
  'db'
);

// Disable minification for production builds to prevent crashes
config.transformer.minifierEnabled = false;

// Ensure proper handling of source maps
config.transformer.getTransformOptions = async () => ({
  transform: {
    experimentalImportSupport: false,
    inlineRequires: false,
  },
});

// Add resolver configuration for better module resolution
config.resolver.platforms = ['native', 'android', 'ios', 'web'];

// Add alias for @ to project root
config.resolver.alias = {
  '@': __dirname,
};

// Add better error handling for resolver
config.resolver.resolverMainFields = ['react-native', 'browser', 'main'];

module.exports = config;