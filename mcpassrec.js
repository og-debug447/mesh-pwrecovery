'use strict';

// MeshCentral Password Recovery plugin (mcpassrec).
// The Password Recovery tab (page 62) is added to the device pages by
// scripts/patch_meshcentral.js; this entry point keeps existing plugin
// lifecycle hooks working (mirrors the reference mckeylog.js).
module.exports.mcpassrec = function (parent) {
    return {
        parent: parent,
        exports: ['onDeviceRefreshEnd'],
        onDeviceRefreshEnd: function () { }
    };
};
