// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Stands in for an external undici copy (spec 055 §3.1): its own core Request class,
// published on the same channel from a file that is not Node's bundled undici.
"use strict";
const { channel } = require("node:diagnostics_channel");

class Request {
    constructor(origin, path) {
        this.method = "POST";
        this.origin = origin;
        this.path = path;
        this.headers = [];
    }
}

exports.publishCreate = (origin, path) => {
    const request = new Request(origin, path);
    channel("undici:request:create").publish({ request });
    return request;
};
