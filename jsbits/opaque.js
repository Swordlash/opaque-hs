// The JavaScript of Crypto.OPAQUE.Client on GHC's WebAssembly and JavaScript
// backends: the calls to @serenity-kit/opaque (opaque-ke compiled to wasm),
// declared in src-serenity/Crypto/OPAQUE/Client.hs. On WebAssembly the file
// is embedded in the program; the JavaScript backend links it (js-sources).
//
// Where the library comes from. opaque_hs_load looks for it once, the first
// time a registration or a login starts:
//
//   1. globalThis.opaqueHsSerenity, when the program or page set it: the
//      module itself, a promise of it, or a function that returns either
//      (a function is called only now, so a page can load the library, about
//      half a megabyte, the first time a password is used);
//   2. otherwise import("@serenity-kit/opaque"), which Node resolves from
//      this file's place, and a browser only through an import map. The name
//      is not written as a literal, so that a bundler leaves the import
//      alone: an application that bundles sets the global.
//
// A step's state is an object { state, password }: serenity's own state, a
// string, and the password, which serenity asks for again at the finish.
// Both are JavaScript strings, which cannot be zeroed; opaque_hs_forget
// drops them.
//
// Everything crosses as serenity carries it: a password and an identity as
// a string, and a message or a key as a string of unpadded base64url. The
// Haskell module encodes and decodes them. A finishing step answers one
// string: "ok" and its results, or "fail" and a status, with spaces
// between. The statuses are the numbers of errorOf in the Haskell module:
//
//   1 a message is invalid    4 the key stretching failed
//   2 the state was dropped   5 a wrong password, or a wrong server
//   3 the server reflected the OPRF's value
//
// Keep this file ASCII: an embedded source is mis-escaped otherwise.

var opaque_hs_module = null;
var opaque_hs_loading = null;

function opaque_hs_load() {
  if (opaque_hs_loading === null) {
    opaque_hs_loading = (async function () {
      var given = globalThis.opaqueHsSerenity;
      var name = "@serenity-kit/opaque";
      var found;
      if (typeof given === "function") found = await given();
      else if (given !== undefined && given !== null) found = await given;
      else found = await import(/* webpackIgnore: true */ /* @vite-ignore */ name);
      await found.ready;
      if (!found.client || typeof found.client.startLogin !== "function") {
        throw new Error("what was loaded is not @serenity-kit/opaque");
      }
      opaque_hs_module = found;
    })().catch(function (error) {
      // The next step tries again: a page's chunk may load the second time.
      opaque_hs_loading = null;
      console.error("opaque-hs: @serenity-kit/opaque could not be loaded:", error);
      throw error;
    });
  }
  return opaque_hs_loading;
}

// What serenity threw, as a status. A message that does not decode names
// the step "deserialize ..."; the wasm module traps (a RuntimeError) when
// Argon2id's memory cannot be allocated, and works again afterwards.
function opaque_hs_status_of(error) {
  var message = String(error && error.message !== undefined ? error.message : error);
  if (error instanceof WebAssembly.RuntimeError || /key ?stretching/i.test(message)) return 4;
  if (message.indexOf("reflected") !== -1) return 3;
  return 1;
}

// Start a login (KE1) or a registration (the request) with the password.
// A promise of { status, state, password, message }; rejected when the
// library cannot be loaded.
function opaque_hs_start(login, password) {
  return opaque_hs_load().then(function () {
    try {
      if (login) {
        var l = opaque_hs_module.client.startLogin({ password: password });
        return { status: 0, state: l.clientLoginState, password: password, message: l.startLoginRequest };
      }
      var r = opaque_hs_module.client.startRegistration({ password: password });
      return { status: 0, state: r.clientRegistrationState, password: password, message: r.registrationRequest };
    } catch (error) {
      return { status: opaque_hs_status_of(error) };
    }
  });
}

function opaque_hs_status(started) {
  return started.status;
}

function opaque_hs_message(started) {
  return started.message;
}

function opaque_hs_forget(state) {
  state.state = null;
  state.password = null;
}

// The arguments both finishing steps share, or a status. An identity is
// given or not, whatever its text: the empty identity is not none.
function opaque_hs_arguments(state, iterations, kib, hasClient, client, hasServer, server) {
  if (opaque_hs_module === null || typeof state.state !== "string" || typeof state.password !== "string") return 2;
  var identifiers = {};
  if (hasClient) identifiers.client = client;
  if (hasServer) identifiers.server = server;
  return {
    password: state.password,
    keyStretching: { "argon2id-custom": { iterations: iterations, memory: kib, parallelism: 1 } },
    identifiers: identifiers,
  };
}

// Finish a login with KE2: KE3, the session key and the export key.
function opaque_hs_finish_login(state, ke2, iterations, kib, hasClient, client, hasServer, server) {
  try {
    var given = opaque_hs_arguments(state, iterations, kib, hasClient, client, hasServer, server);
    if (typeof given === "number") return "fail " + given;
    given.clientLoginState = state.state;
    given.loginResponse = ke2;
    var r = opaque_hs_module.client.finishLogin(given);
    // serenity does not say which: a wrong password, a wrong MAC of the
    // server's, or the OPRF's value reflected.
    if (r === undefined) return "fail 5";
    return "ok " + r.finishLoginRequest + " " + r.sessionKey + " " + r.exportKey;
  } catch (error) {
    return "fail " + opaque_hs_status_of(error);
  }
}

// Finish a registration with the server's response: the record and the
// export key.
function opaque_hs_finish_registration(state, response, iterations, kib, hasClient, client, hasServer, server) {
  try {
    var given = opaque_hs_arguments(state, iterations, kib, hasClient, client, hasServer, server);
    if (typeof given === "number") return "fail " + given;
    given.clientRegistrationState = state.state;
    given.registrationResponse = response;
    var r = opaque_hs_module.client.finishRegistration(given);
    return "ok " + r.registrationRecord + " " + r.exportKey;
  } catch (error) {
    return "fail " + opaque_hs_status_of(error);
  }
}
