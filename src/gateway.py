"""The AI gateway call, and the AIRS verdict that rides back with it.

Ported from the inferd daemon's gateway_service.py. The response document this builds is a
contract: the console parses these exact keys, so a field renamed here is a field the console
silently stops showing.

The scan is attached to every outcome, including outcomes that failed for reasons with nothing
to do with security. Whether a turn was inspected is a separate question from whether it
succeeded, and collapsing the two is the exact mistake this path exists to avoid.

Credential note: the inferd version resolved the gateway key from the database (sealed with
credentials.key) first, and the environment only as a fallback. That database path is tied to the
old IPC credential-store flow and is not ported yet — pretzel-ai reads the key from the
environment (PZ_PORTKEY_API_KEY by default), the documented bootstrap/lab source. Sealed-storage
credentials are a later milestone.
"""

import json
import logging
import secrets
import time
import urllib.error
import urllib.request

# The vendor SDK. The gateway leg goes through it so a customer deployment is reading Portkey's
# own client rather than our hand-rolled HTTP; the bypass leg cannot, because it points at a
# provider endpoint with its own auth shape, so urllib stays for that one. Both legs converge on
# the same (status, doc) pair below and share every line of interpretation after that.
from portkey_ai import Portkey

log = logging.getLogger("pretzel-ai.gateway")

# before_request_hooks is the prompt direction, after_request_hooks the response one. Both are
# read: a turn can be clean on the way out and dirty on the way back, and that asymmetry is
# exactly what a request-only view would miss.
_PHASES = (("before_request_hooks", "prompt"), ("after_request_hooks", "response"))

_DETECTION_FIELDS = ("prompt_detected", "response_detected", "tool_detected")

USER_AGENT = "pz-pretzel-ai/1.0"


def new_tr_id():
    """One LLM round trip. The innermost of the three ids a turn carries.

    Minted here rather than taken from the caller because the unit it names is one this side owns:
    with tool calls a single operator request becomes several model calls, and the prompt and the
    response of each one have to be correlatable to each other and to nothing else. mgmtd's
    transaction_id spans all of them; this does not.
    """
    return "tr_" + secrets.token_hex(8)

# Display names for the integration slugs the catalog uses. A slug with no entry here is not
# dropped — it is shown as-is, so a provider connected tomorrow appears under its own name rather
# than under a blank one.
_PROVIDER_LABELS = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google": "Google",
    "vertex-ai": "Vertex AI",
    "azure-openai": "Azure OpenAI",
    "bedrock": "Bedrock",
}


def _provider_of(model_id):
    """"@openai/gpt-4o" -> "OpenAI". A bare model name has no slug and so no provider."""
    if not model_id.startswith("@") or "/" not in model_id:
        return ""
    slug = model_id[1:].split("/", 1)[0]
    return _PROVIDER_LABELS.get(slug, slug)


def extract_scan(doc):
    """Fold the gateway's hook_results into the shape the console renders."""
    scan = {"present": False}
    hooks = doc.get("hook_results") if isinstance(doc, dict) else None
    if not isinstance(hooks, dict):
        return scan

    categories, masked = [], {}
    present = any_fail = denied = any_async = transformed = timed_out = errored = False
    # A check can fail two ways and they are not the same fact: it can rule against the turn, or it
    # can never rule at all because the call to AIRS itself errored. `ruled` says at least one check
    # came back with a verdict on the content; `check_error` says at least one did not.
    ruled = check_error = False
    latency = 0
    profile = profile_id = scan_id = report_id = action = error_detail = ""

    for key, direction in _PHASES:
        for hook in hooks.get(key) or []:
            if not isinstance(hook, dict):
                continue
            present = True

            # verdict defaults True: a hook that reported no verdict has not failed.
            if hook.get("verdict", True) is False:
                any_fail = True
            denied = denied or bool(hook.get("deny", False))
            any_async = any_async or bool(hook.get("async", False))
            transformed = transformed or bool(hook.get("transformed", False))
            latency = max(latency, hook.get("execution_time") or 0)

            for check in hook.get("checks") or []:
                if not isinstance(check, dict):
                    continue

                # An errored check is read BEFORE its data, because it has none. Portkey reports the
                # failure here and, with fail_on_error off, still lets the turn through with the
                # hook's own verdict left true — so a guardrail that never ran looks identical to
                # one that ran and cleared, unless this branch is the one that speaks.
                err = check.get("error")
                if err:
                    check_error = True
                    if not error_detail:
                        error_detail = (err.get("message", "") if isinstance(err, dict)
                                        else str(err))[:200]

                data = check.get("data")
                if not isinstance(data, dict):
                    continue
                ruled = True

                profile = profile or data.get("profile_name", "")
                profile_id = profile_id or data.get("profile_id", "")
                scan_id = scan_id or data.get("scan_id", "")
                report_id = report_id or data.get("report_id", "")
                action = action or data.get("action", "")
                timed_out = timed_out or bool(data.get("timeout", False))
                errored = errored or bool(data.get("error", False))

                # Every category AIRS reported is carried through, hit or not, with the key names
                # taken from the payload rather than a list compiled here. A category AIRS adds
                # tomorrow then appears on its own; a hard-coded list would drop it, and
                # "not shown" reads identically to "not detected".
                for field in _DETECTION_FIELDS:
                    det = data.get(field)
                    if not isinstance(det, dict):
                        continue
                    for cat_id, hit in det.items():
                        if isinstance(hit, bool):
                            categories.append({"id": cat_id, "direction": direction, "hit": hit})

                # The masked string is computed whenever DLP matches; `transformed` says whether it
                # was the one actually forwarded. Both facts are reported: a mask computed and NOT
                # applied means the original text went upstream.
                pm = data.get("prompt_masked_data")
                if isinstance(pm, dict) and not masked:
                    masked = {
                        "text": pm.get("data", ""),
                        "patterns": [p["pattern"] for p in (pm.get("pattern_detections") or [])
                                     if isinstance(p, dict) and isinstance(p.get("pattern"), str)],
                    }

    if not present:
        return scan  # the guardrail was not on this call's path

    # Four states, not two. "flagged" is one a boolean would hide: AIRS found something and the
    # gateway forwarded it anyway (deny off, or an async guardrail, which cannot deny whatever it
    # found). "not_inspected" is the other, and it is the dangerous one: the hook ran, the call to
    # AIRS errored, fail_on_error was off, and the turn went upstream uninspected. Reported as
    # "allow" that is a green light on a control that never looked — the one reading of this
    # payload that is worse than no reading at all.
    if check_error and not ruled:
        verdict = "not_inspected"
    else:
        verdict = "allow" if not any_fail else ("block" if denied else "flagged")

    scan.update({
        "present": True,
        "verdict": verdict,
        "enforced": denied,
        "async": any_async,
        "action": action,
        "profile": profile,
        "profile_id": profile_id,
        "scan_id": scan_id,
        "report_id": report_id,
        "latency_ms": latency,
        "timeout": timed_out,
        "error": errored or check_error,
        "categories": categories,
    })
    # Only when there is one: an absent key reads as "nothing went wrong", which is true here.
    if error_detail:
        scan["error_detail"] = error_detail
    if masked:
        masked["applied"] = transformed
        scan["masked"] = masked
    return scan


class GatewayService:
    def __init__(self, config, credentials):
        # credentials resolves the gateway key for a credential id; see src/config.py,
        # which reads it from the AIRS values.yaml (PORTKEY_CLIENT_AUTH) or the environment.
        self._gw = config
        self._models = {m["id"]: m for m in config.get("models", [])}
        self._credentials = credentials
        # One SDK client per (base_url, key). Built on first use rather than in the constructor:
        # a bad key should surface on the turn that used it, not by refusing to start the daemon.
        self._clients = {}

    # --- Transport -----------------------------------------------------------------------
    #
    # Two senders, one contract: (status, doc, transport_error). `status` is the HTTP code, `doc`
    # the parsed body — INCLUDING for a guardrail block, because the hook results ride on the 446
    # and losing them would turn "the guardrail denied this" into "something went wrong".

    def _sdk_client(self, route, key):
        """The SDK client for this route, or None when the route cannot be expressed through it."""
        # The SDK owns the "/chat/completions" suffix; base_url is everything before it. A config
        # pointing somewhere else is not an error — it just cannot go through the SDK, and falls
        # back to urllib rather than being rewritten into a shape the operator did not ask for.
        path = route["path"]
        if not path.endswith("/chat/completions"):
            return None
        scheme = "https" if route.get("tls", True) else "http"
        base = f"{scheme}://{route['host']}:{route.get('port', 443)}{path[: -len('/chat/completions')]}"

        cached = self._clients.get(base)
        if cached is None:
            cached = Portkey(base_url=base, api_key=key)
            self._clients[base] = cached
        return cached

    def _send_sdk(self, client, model, messages, token_param, headers, timeout):
        """→ (status, doc, transport_error). Reads the verdict off the exception on a block."""
        try:
            resp = client.chat.completions.create(
                model=model, messages=messages, stream=False,
                extra_headers=headers, timeout=timeout,
                extra_body={token_param: self._gw.get("max_tokens", 4096)})
            return 200, resp.model_dump(), ""
        except Exception as exc:                    # noqa: BLE001 - classified by shape, below
            # Not caught by class on purpose. The SDK raises openai.APIStatusError, but `openai` is
            # vendored inside portkey_ai and is not importable here, so naming the class would mean
            # reaching into a private path that a version bump can move. What matters is stable:
            # an HTTP failure carries a response we can read, a transport failure does not.
            response = getattr(exc, "response", None)
            status = getattr(exc, "status_code", 0) or 0
            if response is None or not status:
                return 0, {}, str(exc)[:300]
            try:
                return status, response.json(), ""
            except Exception:                       # noqa: BLE001 - a non-JSON error body
                return status, {"__raw__": (getattr(response, "text", "") or "")[:400]}, ""

    def _send_urllib(self, url, body, headers, timeout):
        """→ (status, doc, transport_error). The bypass leg, and the SDK's fallback."""
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                status, raw = r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read().decode("utf-8", "replace")
            log.info("HTTP Error received from gateway: status=%d", status)
        except (urllib.error.URLError, OSError) as e:
            return 0, {}, str(getattr(e, "reason", e))
        try:
            return status, json.loads(raw), ""
        except json.JSONDecodeError:
            return status, {"__raw__": " ".join(raw.split())[:400]}, ""

    @property
    def default_model(self):
        return self._gw.get("default_model", "")

    def catalog(self):
        """The model list the console's picker is built from → [{id, label, provider}].

        Derived from config.json rather than mirrored anywhere: the console asks for this over the
        wire (ListModels) so there is exactly one list, and adding a model stays a one-file edit.
        """
        out = []
        for m in self._gw.get("models", []):
            mid = m.get("id", "")
            if not mid:
                continue
            # A model that names no provider gets one from its own routing slug, so the picker can
            # group by provider without the catalog having to repeat itself.
            provider = m.get("provider") or _provider_of(mid)
            out.append({"id": mid, "label": m.get("label") or mid, "provider": provider})
        return out

    def resolve_model(self, requested):
        """An unknown model is not silently substituted — the console shows which model answered,
        and quietly serving a different one makes that display a lie."""
        if not requested:
            return self.default_model, ""
        if requested in self._models:
            return requested, ""
        return "", f"unknown model '{requested}'"

    def build_messages(self, message, system_prompt=None, history=None):
        """system prompt, then the conversation so far, then this turn.

        History goes in as user/assistant pairs rather than folded into the system prompt or into
        `message`, and the difference is not cosmetic here: the AIRS guardrail's scan scope is
        `last_message`, so only the final entry is inspected. Anything appended to the system
        prompt is therefore never scanned at all — measured, not assumed — which makes "put the
        context in the system prompt" the one arrangement that hides it from the control.
        """
        messages = []
        prompt = system_prompt if system_prompt is not None else self._gw.get("system_prompt", "")
        if prompt:
            messages.append({"role": "system", "content": prompt})

        for turn in history or []:
            role = (turn.get("role") or "").strip()
            content = turn.get("content") or ""
            # An unknown role is dropped rather than coerced to "user": a mislabelled assistant turn
            # replayed as the person's own words rewrites what the model thinks it already said.
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": message})
        return messages

    def _resolve_route(self, model):
        """Where this turn goes: the gateway, or straight to the provider. → (route, error)

        The route carries everything that differs between the two — host, path, auth header shape,
        and the credential id to look the key up under — so complete() has one code path.
        """
        if not self._gw.get("bypass_gateway"):
            return {
                "bypass": False,
                "host": self._gw["host"],
                "port": self._gw.get("port", 443),
                # A co-located self-hosted AIRS gateway is plain HTTP on its container port; the
                # hosted gateway is HTTPS. tls defaults on so an unset config stays secure.
                "tls": self._gw.get("tls", True),
                "path": self._gw["path"],
                "api_key_header": self._gw["api_key_header"],
                "api_key_prefix": "",
                "credential_id": self._gw.get("id", "portkey"),
            }, ""

        provider = (self._models.get(model) or {}).get("provider", "")
        if not provider:
            return None, (f"bypass is on but the model '{model}' declares no provider, "
                          f"so there is nowhere to send it directly")

        direct = (self._gw.get("direct") or {}).get(provider)
        if not direct:
            return None, (f"bypass is on but no direct endpoint is configured for provider "
                          f"'{provider}' (only OpenAI-compatible providers are supported)")

        return {
            "bypass": True,
            "host": direct["host"],
            "port": direct.get("port", 443),
            "path": direct["path"],
            "api_key_header": direct.get("api_key_header", "Authorization"),
            "api_key_prefix": direct.get("api_key_prefix", "Bearer "),
            "tls": direct.get("tls", True),
            "credential_id": provider,
        }, ""

    def complete(self, model, messages, session_id="", transaction_id=""):
        """Returns the response document the console consumes, whatever happened."""
        started = time.monotonic()
        tr_id = new_tr_id()
        out = {"model": model, "tr_id": tr_id}
        if transaction_id:
            out["transaction_id"] = transaction_id
        if session_id:
            out["session_id"] = session_id

        log.info("Starting complete request: model=%s, messages_count=%d, session=%s, txn=%s, tr=%s",
                 model, len(messages), session_id or "(none)",
                 transaction_id or "(none)", tr_id)

        # Which endpoint this turn goes to.
        route, route_err = self._resolve_route(model)
        if route_err:
            out.update({"ok": False, "code": "BAD_ROUTE", "error": route_err, "latency_ms": 0})
            log.error("Route resolution failed for model '%s': %s", model, route_err)
            return out

        key = self._credentials.key(route["credential_id"])
        if not key:
            out.update({"ok": False, "code": "NO_CREDENTIAL",
                        "error": (f"no credential for '{route['credential_id']}' is configured on "
                                  f"this appliance"),
                        "latency_ms": 0})
            log.error("Missing credentials for credential_id '%s'", route['credential_id'])
            return out

        # Which name the output cap goes out under is a per-model fact, not a global one: the gpt-5
        # generation rejects `max_tokens` outright ("Unsupported parameter") and wants
        # `max_completion_tokens`, while gpt-4o and Gemini take the old name. The catalog carries
        # it so adding a model that flipped is a config edit, not a code edit; unset means the old
        # name, which is what every model before this took.
        token_param = (self._models.get(model) or {}).get("token_param", "max_tokens")
        timeout = self._gw.get("timeout_sec", 45)

        # Headers the SDK does not set for us. The api-key header is deliberately NOT here for the
        # SDK leg — the client already holds the credential, and sending it twice under two names
        # is how a rotated key ends up half-applied.
        extra = dict(self._gw.get("headers") or {})
        # The gateway leg can carry exactly one id: Portkey forwards x-portkey-trace-id to AIRS as
        # its tr_id, and its plugin sets nothing else (see plugins/panw-prisma-airs/intercept.ts).
        # session_id keeps that slot because grouping a thread in the AIRS console is the one thing
        # the field can still buy here. The three-level scheme lands properly on the direct scan
        # path, which sets tr_id, session_id and transaction_id as their own fields.
        if session_id:
            extra["x-portkey-trace-id"] = session_id

        client = None if route["bypass"] else self._sdk_client(route, key)

        if client is not None:
            log.debug("Sending via Portkey SDK (model=%s)", model)
            status, doc, transport_error = self._send_sdk(
                client, model, messages, token_param, extra, timeout)
        else:
            scheme = "https" if route.get("tls", True) else "http"
            url = f"{scheme}://{route['host']}:{route.get('port', 443)}{route['path']}"
            body = json.dumps({
                "model": model,
                token_param: self._gw.get("max_tokens", 4096),
                "messages": messages,
                "stream": False,
            }).encode()
            headers = {"Content-Type": "application/json",
                       "User-Agent": USER_AGENT,
                       route["api_key_header"]: route.get("api_key_prefix", "") + key,
                       **extra}
            log.debug("Sending HTTP POST to %s (bypass=%s)", url, route.get("bypass", False))
            status, doc, transport_error = self._send_urllib(url, body, headers, timeout)

        out["latency_ms"] = int((time.monotonic() - started) * 1000)

        if transport_error:
            out.update({"ok": False, "code": "UNREACHABLE",
                        "error": transport_error or "could not reach the gateway"})
            log.warning("chat turn failed to leave (latency=%dms): %s",
                        out["latency_ms"], transport_error)
            return out

        # A body that would not parse is reported as itself rather than as a missing completion:
        # "the gateway said something we could not read" and "the gateway said nothing" are
        # different failures and lead an operator to different places.
        if "__raw__" in doc:
            out.update({"ok": False, "code": "BAD_RESPONSE", "status": status,
                        "error": f"gateway response was not JSON: {doc['__raw__']}"})
            log.warning("chat turn unreadable (status=%s, latency=%dms)", status, out["latency_ms"])
            return out

        out["scan"] = extract_scan(doc)
        out["status"] = status
        if route["bypass"]:
            out["bypassed"] = True

        err = doc.get("error") if isinstance(doc, dict) else None
        err_type = err.get("type", "") if isinstance(err, dict) else ""
        err_msg = err.get("message", "") if isinstance(err, dict) else ""

        if not err_msg and isinstance(doc, dict) and doc.get("status") == "failure":
            err_msg = doc.get("message", "") or "the gateway rejected the request"
            err_type = err_type or "gateway_rejected"

        soft_denied = False
        for key, _ in _PHASES:
            for hook in (doc.get("hook_results") or {}).get(key) or []:
                if isinstance(hook, dict) and (hook.get("deny") or hook.get("softDeny200")):
                    soft_denied = True

        # 446 또는 가드레일 차단 처리
        if status == 446 or err_type == "hooks_failed" or soft_denied:
            out.update({"ok": False, "code": "BLOCKED",
                        "error": err_msg or "the guardrail denied this turn"})
            log.info("chat turn blocked by guardrail (status=%s, scan_id=%s, verdict=%s, latency=%dms)",
                     status, out["scan"].get("scan_id", ""), out["scan"].get("verdict", ""), out["latency_ms"])
            return out

        if err_type or err_msg:
            out.update({"ok": False, "code": "UPSTREAM_ERROR", "upstream_type": err_type,
                        "error": err_msg or "the provider returned an error"})
            log.warning("chat turn upstream error (status=%s, type=%s, msg=%s, latency=%dms)",
                        status, err_type, err_msg[:100], out["latency_ms"])
            return out

        text = None
        choices = doc.get("choices") if isinstance(doc, dict) else None
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            msg = choices[0].get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                text = msg["content"]

        if text is None:
            out.update({"ok": False, "code": "BAD_RESPONSE",
                        "error": "gateway response carried no completion"})
            log.warning("chat turn had no completion (status=%s, latency=%dms)", status, out["latency_ms"])
            return out

        out["ok"] = True
        out["reply"] = text
        if isinstance(doc.get("usage"), dict):
            out["usage"] = doc["usage"]

        # [LOG] 최종 성공 로그 (소요 시간 및 응답 글자 수 기록)
        log.info("chat turn completed successfully (status=%s, reply_chars=%d, latency=%dms)",
                 status, len(text), out["latency_ms"])

        return out


    def complete_turn(self, model_req, message, system_prompt=None, history=None, session_id="",
                      transaction_id=""):
        """One non-retrieval turn: resolve the model, build the messages, call the gateway.

        Retrieval/grounding (the old chat_service.handle_turn) is intentionally not ported here —
        the console's RAG controls were removed, so every turn is a straight gateway call.
        """
        message = (message or "").strip()
        if not message:
            return {"ok": False, "code": "BAD_REQUEST", "error": "message is required"}

        model, model_err = self.resolve_model(model_req)
        if model_err:
            return {"ok": False, "code": "BAD_REQUEST", "error": model_err}

        return self.complete(model,
                             self.build_messages(message, system_prompt or None, history),
                             session_id, transaction_id)
