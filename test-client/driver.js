// The JavaScript of test-client/Main.hs, a program for Node: the lines of
// standard input one at a time, a line of standard output, and
// serenity-kit's server for the program's test of itself.
//
// Keep this file ASCII: an embedded source is mis-escaped otherwise.

var opaque_hs_test_lines = null;

// A promise of the next line of standard input, or of null at its end.
function opaque_hs_test_line() {
  if (opaque_hs_test_lines === null) {
    opaque_hs_test_lines = import("node:readline").then(function (readline) {
      return readline.createInterface({ input: process.stdin })[Symbol.asyncIterator]();
    });
  }
  return opaque_hs_test_lines
    .then(function (lines) {
      return lines.next();
    })
    .then(function (next) {
      return next.done ? null : next.value;
    });
}

function opaque_hs_test_say(text) {
  process.stdout.write(text + "\n");
}

// serenity-kit's server, found as jsbits/opaque.js finds the library. Each
// function takes and gives words: base64url, as serenity carries them.
var opaque_hs_test_serenity = null;

function opaque_hs_test_server() {
  var given = globalThis.opaqueHsSerenity;
  var name = "@serenity-kit/opaque";
  var loading = typeof given === "function" ? given() : given !== undefined && given !== null ? given : import(name);
  return Promise.resolve(loading).then(function (found) {
    return found.ready.then(function () {
      opaque_hs_test_serenity = found;
      return found.server.createSetup();
    });
  });
}

function opaque_hs_test_registration_response(setup, user, request) {
  return opaque_hs_test_serenity.server.createRegistrationResponse({
    serverSetup: setup,
    userIdentifier: user,
    registrationRequest: request,
  }).registrationResponse;
}

// The server's state and KE2, with a space between them. An empty record
// is no record: the server answers with a fake one.
function opaque_hs_test_start_login(setup, user, record, ke1) {
  var r = opaque_hs_test_serenity.server.startLogin({
    serverSetup: setup,
    userIdentifier: user,
    registrationRecord: record === "" ? null : record,
    startLoginRequest: ke1,
  });
  return r.serverLoginState + " " + r.loginResponse;
}

// The session key, or "" when the server refuses KE3.
function opaque_hs_test_finish_login(state, ke3) {
  try {
    return opaque_hs_test_serenity.server.finishLogin({ serverLoginState: state, finishLoginRequest: ke3 }).sessionKey;
  } catch (error) {
    return "";
  }
}

// What WebCrypto says of a key: its algorithm, whether it can be exported,
// and its usages.
function opaque_hs_test_key_facts(key) {
  return key.algorithm.name + " " + key.extractable + " " + key.usages.join(",");
}

// HKDF-SHA-512 with no salt and this info over a key: a promise of 64
// bytes, in base64url.
function opaque_hs_test_derive(key, info) {
  var how = { name: "HKDF", hash: "SHA-512", salt: new Uint8Array(0), info: new TextEncoder().encode(info) };
  return crypto.subtle.deriveBits(how, key, 512).then(function (bits) {
    return Buffer.from(bits).toString("base64url");
  });
}

// A promise of whether WebCrypto refuses to export the key.
function opaque_hs_test_export_refused(key) {
  return crypto.subtle.exportKey("raw", key).then(
    function () {
      return false;
    },
    function () {
      return true;
    },
  );
}

// Bytes, in base64url, as a key of HKDF: what the test compares a held
// export key with.
function opaque_hs_test_import(text) {
  return crypto.subtle.importKey("raw", Buffer.from(text, "base64url"), "HKDF", false, ["deriveBits"]);
}
