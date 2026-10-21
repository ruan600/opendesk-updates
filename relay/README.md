# OpenDesk public relay on Render Free

The root `Dockerfile`, `.dockerignore` and `render.yaml` deploy the existing .NET 10 relay as one Free web service. There are no databases, paid instances, disks or other resources in the blueprint. Render terminates trusted HTTPS/WSS; the container listens on `0.0.0.0:10000` behind that proxy and runs as the .NET image's non-root app user. `/health` must return HTTP 200. `/ws` handles the application WebSocket protocol.

The Docker build context uses an explicit allowlist: only the Dockerfile, ignore file and two relay source files are included. Do not upload the entire workspace to a repository. Publisher keys in `private/`, desktop configuration, packaged binaries and user settings are not deployment inputs.

Deploy the repository containing those relay sources and deployment files through a connected Render account. Confirm **Free** for the web service and retain one instance: pairing state currently resides in one process. Use the actual assigned service hostname, not a guessed name. After deployment, test its `/health` endpoint and run the relay integration suite with `wss://<actual-hostname>/ws` before bundling that URL into a new Windows release. Do not replace the client's default with an unverified hostname.

## Free-tier operating limits

Render's Free web service sleeps after 15 minutes without inbound HTTP traffic or WebSocket messages and takes about one minute to wake when a request/new connection arrives. WebSocket message traffic counts as activity. Existing connections can be lost during restarts, deploys or sleep; hosts need reconnect behavior. An unattended host waiting without message activity may sleep, so viewer connection/wake and host reconnect must be tested together.

Each workspace receives 750 Free instance hours per calendar month, shared by its Free services. Exhausting hours suspends those services until the next month. Outbound bandwidth and build minutes have workspace allowances; check the connected account's current allowances rather than assuming unlimited screen/audio/file traffic. Render may restart Free services at any time and does not recommend this tier for production applications. It is suitable for a limited-use preview, not an always-available or unlimited AnyDesk replacement.

Keep this deployment on Free and do not add a payment method or upgrade. A workspace with an existing payment method can incur supplementary bandwidth/build charges under Render's policy; review that account's billing controls before deployment. Without a payment method, quota exhaustion suspends service/builds rather than providing unlimited capacity.

Official references: [Free service limits](https://render.com/docs/free), [WebSocket support](https://render.com/docs/websocket), [Blueprint fields](https://render.com/docs/blueprint-spec).
