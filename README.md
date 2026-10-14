# otp load harness

qa load-testing harness for sms notification pipelines. two parts:

- **scan** — discovers verification/otp dispatch endpoints on configured domains
- **dispatch** — sends notification requests to a recipient number at a controlled rate

## run locally

    npm install
    node server.js

open http://localhost:3000

## run on termux

    pkg install -y nodejs git
    git clone <repo>
    cd otp-load-harness
    npm install
    node server.js

## env vars

- `PORT` — default 3000
- `RPS` — requests per second for dispatch, default 10
- `PROXIES` — comma-separated proxy urls
- `ENDPOINTS_FILE` — custom path for endpoints.json