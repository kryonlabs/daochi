# Lumi conversation and app feedback

Inbe and Harmony send Lumi requests to `POST /api/v1/chat/completions` with
their existing Daochi account token. Daochi keeps the model key on the node,
adds Lumi's instructions, and forwards bounded conversation, app context and
tool definitions. The app validates and executes tool calls against its current
state, then returns their results for the next model reply.

Configure `DAOCHI_CHAT_API_KEY_FILE`, `DAOCHI_CHAT_MODEL` and optionally
`DAOCHI_CHAT_ENDPOINT`. The default endpoint is the standard Z.ai API. The
coding endpoint is `https://api.z.ai/api/coding/paas/v4/chat/completions`;
use it only with the account's applicable provider entitlement. GLM-5 models
use enabled thinking, low reasoning effort and a 2,048-token output cap;
other models use disabled thinking and a 256-token cap.

`scripts/configure-chat.py` probes the selected endpoint before installing a
key privately. It accepts `--provider coding --model glm-5.3-flash
--key-name GLM_API_KEY`, plus `--env-file`, `--host` and `--install-key`.
It preserves unrelated node configuration. Restart the service after deploying
the tested server binary. Never put the provider key into an app bundle.

Daily allowances default to 20 model requests per account and 1,000 per node.
`DAOCHI_CHAT_DAILY_LIMIT` and `DAOCHI_CHAT_GLOBAL_DAILY_LIMIT` override them.
Each provider attempt or tool continuation consumes one unit; usage persists
across restarts. Feedback delivery is independent of the chat allowance.

`POST /api/v1/feedback` saves an account's report idempotently. The app's
durable outbox retries delivery, including when online conversation is disabled.
Explicit `fix ...`, `please fix ...` and `/feedback ...` messages work offline.
Reports contain the user's message and app diagnostics, without copying diary,
task or habit content into diagnostics.

The developer harness reads `GET /api/v1/admin/feedback` with `X-Daochi-Admin`.
The inbox includes `account_id` and the account's public `account_alias` (empty
when it has none). Reply through
`POST /api/v1/admin/feedback/reply` with `account_id`, `id` and `reply`.
Both operator endpoints are disabled unless `DAOCHI_FEEDBACK_TOKEN_FILE`,
`DAOCHI_FEEDBACK_TOKEN` or the existing `DAOCHI_ADMIN_TOKEN` is configured.
The installer creates a private feedback token when none exists, keeping other
node administration settings intact.
Replies are scoped to the reporting account, including when two accounts use
the same report ID. Lumi reads `GET /api/v1/feedback?replies=1&offset=0`, two
replies per page, and attributes developer replies explicitly.

`scripts/feedback.py --host USER@NODE inbox` lets the local developer harness
read reports without receiving the node's admin credential. To send an authored
reply, use `reply --account-id ACCOUNT --report-id REPORT --reply-file FILE`.
The remote helper reads the node's private credential and uses loopback HTTP;
reply text travels as JSON over SSH, without being interpolated into commands.

The dedicated Telegram bot is `@inlumi_bot`. Users link their private chat from
Lumi in Inner Breeze using a one-use link. Account signing keys stay in the app.
`/help` lists the same catalogue used for Telegram's command menu, with examples
for tasks, habits, diary entries, progress and feedback. `/app` and `/history`
open Inner Breeze. App actions require the linked app to remain open and the
corresponding sub-app to be installed. Feedback still asks for approval.
Telegram is input-only for the Lumi conversation. Incoming messages and their
Lumi responses remain in the app's full history and encrypted account sync.
App messages, responses and activity never mirror to the bot. The legacy
`POST /api/v1/lumi/telegram/messages` endpoint validates and acknowledges older
client uploads without any external delivery, including stale queued history.
Direct bot linking, help and explicit authorization acknowledgements remain.

Commands addressed to another bot are ignored; addressed Lumi commands preserve
their argument text. Empty required arguments receive usage instructions.

Check the menu and profile with `python3 scripts/configure-lumi-bot.py --host
USER@NODE`; add `--apply` to update and verify them. The helper reads the node's
existing `/etc/daochi/daochi.env` or a supplied `--env-file`, including
`DAOCHI_LUMI_BOT_TOKEN_FILE`. A local `--token-file` is also supported. It verifies
the bot's identity before making changes and never prints the credential.
Configure `DAOCHI_LUMI_WEBHOOK_SECRET_FILE` and register the authenticated
`/api/v1/lumi/telegram/webhook` endpoint separately after deploying the server.
