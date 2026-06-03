import * as opaque from "@serenity-kit/opaque";

console.log("loading opaque library");
await opaque.ready;
console.log("opaque library finished loading");

const clientId = "demo-user";
const password = "super secret password";

const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
    password,
});

console.log("registration state:", clientRegistrationState);
console.log("registration request:", registrationRequest);

const res1 = await fetch("http://127.0.0.1:1337/api/opaque/register/start", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
    },
    body: JSON.stringify({
        clientId,
        payload: registrationRequest,
    }),
});

const registrationResponse = await res1.text();

const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState,
    password,
    registrationResponse,
});

console.log("registrationRecord:", registrationRecord);

const res2 = await fetch("http://127.0.0.1:1337/api/opaque/register/finish", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
    },
    body: JSON.stringify({
        clientId,
        payload: registrationRecord,
    }),
});

console.log(await res2.text());

const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
    password
});

const res3 = await fetch("http://127.0.0.1:1337/api/opaque/login/start", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
    },
    body: JSON.stringify({
        clientId,
        payload: startLoginRequest,
    }),
})

const loginResponse = await res3.text();

const res = opaque.client.finishLogin({
    clientLoginState,
    password,
    loginResponse
});

if (!res)  {
    console.error("failed to login");
} else {
    const { finishLoginRequest, sessionKey } = res;
    console.log("session key:", sessionKey);

    const res4 = await fetch("http://127.0.0.1:1337/api/opaque/login/finish", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            clientId,
            payload: finishLoginRequest,
        }),
    });

    console.log(await res4.text());
}

