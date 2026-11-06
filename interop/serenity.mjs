// The other side of opaque's interoperability tests (opaque/test/Test/Interop.hs):
// @serenity-kit/opaque, opaque-ke compiled to wasm, which the wiki's
// browser client uses. It reads one command per line on standard input and
// answers one line on standard output, words separated by spaces:
//
//   client-start-registration PASSWORD          -> STATE REQUEST
//   client-finish-registration STATE RESPONSE PASSWORD ITERATIONS KIB CLIENT SERVER
//                                               -> RECORD EXPORT_KEY
//   client-start-login PASSWORD                 -> STATE KE1
//   client-finish-login STATE KE2 PASSWORD ITERATIONS KIB CLIENT SERVER
//                                               -> KE3 SESSION_KEY EXPORT_KEY, or "fail"
//   server-setup                                -> SETUP
//   server-registration-response SETUP USER REQUEST -> RESPONSE
//   server-start-login SETUP USER RECORD KE1 CLIENT SERVER -> STATE KE2
//   server-finish-login STATE KE3 CLIENT SERVER -> SESSION_KEY, or "fail"
//
// Messages, states and keys are serenity's own unpadded base64url. A
// password, a user identifier and an identity are UTF-8 text in unpadded
// base64url after a "t" (so that empty text is still a word); "-" is no
// identity, and no record. The first line it writes is
// "ready", or "missing" when the package is not installed.
import { createInterface } from "node:readline";

let opaque;
try {
  opaque = await import("@serenity-kit/opaque");
  await opaque.ready;
} catch {
  console.log("missing");
  process.exit(0);
}
console.log("ready");

const text = (word) => Buffer.from(word.slice(1), "base64url").toString("utf8");
const identifiers = (client, server) => {
  const ids = {};
  if (client !== "-") ids.client = text(client);
  if (server !== "-") ids.server = text(server);
  return ids;
};
const stretching = (iterations, kib) => ({
  "argon2id-custom": { iterations: Number(iterations), memory: Number(kib), parallelism: 1 },
});

const commands = {
  "client-start-registration": (password) => {
    const r = opaque.client.startRegistration({ password: text(password) });
    return [r.clientRegistrationState, r.registrationRequest];
  },
  "client-finish-registration": (state, response, password, iterations, kib, client, server) => {
    const r = opaque.client.finishRegistration({
      clientRegistrationState: state,
      registrationResponse: response,
      password: text(password),
      keyStretching: stretching(iterations, kib),
      identifiers: identifiers(client, server),
    });
    return [r.registrationRecord, r.exportKey];
  },
  "client-start-login": (password) => {
    const r = opaque.client.startLogin({ password: text(password) });
    return [r.clientLoginState, r.startLoginRequest];
  },
  "client-finish-login": (state, ke2, password, iterations, kib, client, server) => {
    const r = opaque.client.finishLogin({
      clientLoginState: state,
      loginResponse: ke2,
      password: text(password),
      keyStretching: stretching(iterations, kib),
      identifiers: identifiers(client, server),
    });
    return r === undefined ? ["fail"] : [r.finishLoginRequest, r.sessionKey, r.exportKey];
  },
  "server-setup": () => [opaque.server.createSetup()],
  "server-registration-response": (setup, user, request) => [
    opaque.server.createRegistrationResponse({ serverSetup: setup, userIdentifier: text(user), registrationRequest: request })
      .registrationResponse,
  ],
  "server-start-login": (setup, user, record, ke1, client, server) => {
    const r = opaque.server.startLogin({
      serverSetup: setup,
      userIdentifier: text(user),
      registrationRecord: record === "-" ? null : record,
      startLoginRequest: ke1,
      identifiers: identifiers(client, server),
    });
    return [r.serverLoginState, r.loginResponse];
  },
  "server-finish-login": (state, ke3, client, server) => {
    try {
      return [opaque.server.finishLogin({ serverLoginState: state, finishLoginRequest: ke3, identifiers: identifiers(client, server) }).sessionKey];
    } catch {
      return ["fail"];
    }
  },
};

for await (const line of createInterface({ input: process.stdin })) {
  const [name, ...args] = line.trim().split(" ");
  try {
    console.log(commands[name](...args).join(" "));
  } catch (error) {
    console.log(`error ${String(error?.message ?? error).replaceAll("\n", " ")}`);
  }
}
