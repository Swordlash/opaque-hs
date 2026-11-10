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
// Bytes cross as Uint8Arrays. A finishing step answers one Uint8Array: a
// status byte, and after a 0 the bytes of its results one after another.
// The statuses are the numbers of errorOf in the Haskell module:
//
//   0 done                 3 the server reflected the OPRF's value
//   1 a message is invalid 4 the key stretching failed
//   2 the state was dropped 5 a wrong password, or a wrong server
//                          6 text that is not UTF-8
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

// Unpadded base64url, as serenity carries every message, state and key.
function opaque_hs_bytes(text) {
  var binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function opaque_hs_base64(bytes) {
  var binary = "";
  for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// The text UTF-8 bytes spell; throws when they are not UTF-8. A byte order
// mark at the start stays, as any other character: serenity must hash the
// bytes the caller gave.
function opaque_hs_text(bytes) {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
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

// Start a login (KE1) or a registration (the request) with the password's
// UTF-8 bytes, which are zeroed here. A promise of { status, state,
// password, message }; rejected when the library cannot be loaded.
function opaque_hs_start(login, password) {
  var text = null;
  try {
    text = opaque_hs_text(password);
  } catch (error) {
    text = null;
  }
  password.fill(0);
  return opaque_hs_load().then(function () {
    if (text === null) return { status: 6 };
    try {
      if (login) {
        var l = opaque_hs_module.client.startLogin({ password: text });
        return { status: 0, state: l.clientLoginState, password: text, message: opaque_hs_bytes(l.startLoginRequest) };
      }
      var r = opaque_hs_module.client.startRegistration({ password: text });
      return { status: 0, state: r.clientRegistrationState, password: text, message: opaque_hs_bytes(r.registrationRequest) };
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
// null for none, or its UTF-8 bytes; empty bytes are the empty identity,
// which is not none.
function opaque_hs_arguments(state, iterations, kib, client, server) {
  if (opaque_hs_module === null || typeof state.state !== "string" || typeof state.password !== "string") return 2;
  var identifiers = {};
  try {
    if (client !== null) identifiers.client = opaque_hs_text(client);
    if (server !== null) identifiers.server = opaque_hs_text(server);
  } catch (error) {
    return 6;
  }
  return {
    password: state.password,
    keyStretching: { "argon2id-custom": { iterations: iterations, memory: kib, parallelism: 1 } },
    identifiers: identifiers,
  };
}

// A status of 0 and the bytes of each base64url word after it.
function opaque_hs_answer(words) {
  var parts = words.map(opaque_hs_bytes);
  var length = 1;
  for (var i = 0; i < parts.length; i++) length += parts[i].length;
  var answer = new Uint8Array(length);
  var at = 1;
  for (var j = 0; j < parts.length; j++) {
    answer.set(parts[j], at);
    at += parts[j].length;
    parts[j].fill(0);
  }
  return answer;
}

// Finish a login with KE2: KE3, the session key and the export key.
function opaque_hs_finish_login(state, ke2, iterations, kib, client, server) {
  try {
    var given = opaque_hs_arguments(state, iterations, kib, client, server);
    if (typeof given === "number") return Uint8Array.of(given);
    given.clientLoginState = state.state;
    given.loginResponse = opaque_hs_base64(ke2);
    var r = opaque_hs_module.client.finishLogin(given);
    // serenity does not say which: a wrong password, a wrong MAC of the
    // server's, or the OPRF's value reflected.
    if (r === undefined) return Uint8Array.of(5);
    return opaque_hs_answer([r.finishLoginRequest, r.sessionKey, r.exportKey]);
  } catch (error) {
    return Uint8Array.of(opaque_hs_status_of(error));
  }
}

// Finish a registration with the server's response: the record and the
// export key.
function opaque_hs_finish_registration(state, response, iterations, kib, client, server) {
  try {
    var given = opaque_hs_arguments(state, iterations, kib, client, server);
    if (typeof given === "number") return Uint8Array.of(given);
    given.clientRegistrationState = state.state;
    given.registrationResponse = opaque_hs_base64(response);
    var r = opaque_hs_module.client.finishRegistration(given);
    return opaque_hs_answer([r.registrationRecord, r.exportKey]);
  } catch (error) {
    return Uint8Array.of(opaque_hs_status_of(error));
  }
}
