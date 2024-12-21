const { synapse, safesynapse } = require("../dist/index.cjs");

// Allow mixed default and named exports
synapse.synapse = synapse;
synapse.safesynapse = safesynapse;

module.exports = synapse;
