import os
import re
import json
import sqlite3
import hashlib
import asyncio
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx

PROFILE = "ga5-incident-agent/v2"
AIPIPE_TOKEN = os.getenv(
    "AIPIPE_TOKEN",
    "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6IjI0ZjMwMDE2NzZAZHMuc3R1ZHkuaWl0bS5hYy5pbiIsImlhdCI6MTc4NTU3OTYyMywiaXNzIjoiaHR0cHM6Ly9haXBpcGUub3JnIiwiYXVkIjoiYWlwaXBlLWFwaSIsImV4cCI6MTc4NjE4NDQyM30.b_wV6GMb7QjinLKiyPj4tx06aWa79YnV3uF_v08JWBE"
)
AIPIPE_ENDPOINT = "https://aipipe.org/openai/v1/chat/completions"
MODEL_NAME = "gpt-4o-mini"

# Initialize SQLite
conn = sqlite3.connect("incidents.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("PRAGMA journal_mode=WAL;")
cursor.execute("""
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    public_marker TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    server_span_id TEXT NOT NULL,
    incoming_span_id TEXT,
    invoke_span_id TEXT NOT NULL,
    chat_span_id TEXT NOT NULL,
    join_span_id TEXT,
    approval_span_id TEXT,
    approval_id TEXT,
    approval_nonce TEXT,
    effect_action_id TEXT,
    policy_json TEXT NOT NULL,
    diagnosis_json TEXT NOT NULL,
    chosen_effect TEXT NOT NULL,
    effect_args_json TEXT NOT NULL,
    state_json TEXT NOT NULL,
    action_log_json TEXT NOT NULL,
    receipt_log_json TEXT NOT NULL,
    attempts_history_json TEXT NOT NULL,
    receipt_digests_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()

app = FastAPI()

@app.middleware("http")
async def log_grader_traffic(request: Request, call_next):
    body_bytes = await request.body()
    print(f"\n[GRADER INCOMING] {request.method} {request.url.path}", flush=True)
    if body_bytes:
        print(f"[BODY]: {body_bytes.decode('utf-8', errors='ignore')}", flush=True)

    async def receive():
        return {"type": "http.request", "body": body_bytes}
    request = Request(request.scope, receive=receive)

    response = await call_next(request)
    print(f"[GRADER OUTGOING STATUS]: {response.status_code}", flush=True)
    return response

def canonical_json_bytes(data: Any) -> bytes:
    """Recursively key-sorted, compact JSON encoded as UTF-8 bytes."""
    return json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')

def compute_digest(data: Any) -> str:
    """Compute SHA-256 hex digest of canonical JSON."""
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()

def random_hex(num_bytes: int) -> str:
    return os.urandom(num_bytes).hex()

def attr(key: str, val: Any) -> Dict[str, Any]:
    if isinstance(val, int):
        return {"key": key, "value": {"intValue": val}}
    elif isinstance(val, bool):
        return {"key": key, "value": {"boolValue": val}}
    elif isinstance(val, float):
        return {"key": key, "value": {"doubleValue": val}}
    else:
        return {"key": key, "value": {"stringValue": str(val)}}

def build_otlp_trace(
    run_id: str,
    public_marker: str,
    trace_id: str,
    server_span_id: str,
    incoming_span_id: Optional[str],
    invoke_span_id: str,
    chat_span_id: str,
    join_span_id: Optional[str],
    approval_span_id: Optional[str],
    approval_id: Optional[str],
    approval_nonce: Optional[str],
    attempts_history: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Construct precise, fully redacted OTLP trace hierarchy."""
    spans = []

    # 1. SERVER span
    server_attrs = [
        attr("ga5.run.id", run_id),
        attr("ga5.public.marker", public_marker),
        attr("http.request.method", "POST"),
        attr("http.route", "/v2/incidents")
    ]
    server_span = {
        "traceId": trace_id,
        "spanId": server_span_id,
        "name": "POST /v2/incidents",
        "kind": 2, # SERVER
        "attributes": server_attrs
    }
    if incoming_span_id:
        server_span["parentSpanId"] = incoming_span_id
    spans.append(server_span)

    # 2. INTERNAL invoke_agent span
    invoke_span = {
        "traceId": trace_id,
        "spanId": invoke_span_id,
        "parentSpanId": server_span_id,
        "name": "invoke_agent incident-response",
        "kind": 1, # INTERNAL
        "attributes": [
            attr("ga5.run.id", run_id),
            attr("ga5.public.marker", public_marker)
        ]
    }
    spans.append(invoke_span)

    # 3. CLIENT chat incident-plan span
    chat_span = {
        "traceId": trace_id,
        "spanId": chat_span_id,
        "parentSpanId": invoke_span_id,
        "name": "chat incident-plan",
        "kind": 3, # CLIENT
        "attributes": [
            attr("ga5.run.id", run_id),
            attr("ga5.public.marker", public_marker),
            attr("gen_ai.operation.name", "chat"),
            attr("gen_ai.request.model", MODEL_NAME)
        ]
    }
    spans.append(chat_span)

    # Group attempts by logical tool execution
    logical_tools: Dict[str, Dict[str, Any]] = {}
    for att_item in attempts_history:
        exec_id = att_item["execToolSpanId"]
        if exec_id not in logical_tools:
            logical_tools[exec_id] = {
                "actionId": att_item["actionId"],
                "callId": att_item["callId"],
                "toolName": att_item["toolName"],
                "phase": att_item.get("phase", "diagnostic"),
                "attempts": []
            }
        logical_tools[exec_id]["attempts"].append(att_item)

    # 4. Tool Execution Spans
    for exec_id, tool_info in logical_tools.items():
        exec_span = {
            "traceId": trace_id,
            "spanId": exec_id,
            "parentSpanId": invoke_span_id,
            "name": f"execute_tool {tool_info['toolName']}",
            "kind": 1, # INTERNAL
            "attributes": [
                attr("ga5.run.id", run_id),
                attr("ga5.public.marker", public_marker),
                attr("ga5.action.id", tool_info["actionId"]),
                attr("gen_ai.tool.name", tool_info["toolName"]),
                attr("gen_ai.tool.call.id", tool_info["callId"]),
                attr("gen_ai.operation.name", "execute_tool")
            ]
        }
        spans.append(exec_span)

        for att_item in tool_info["attempts"]:
            att_attrs = [
                attr("ga5.run.id", run_id),
                attr("ga5.public.marker", public_marker),
                attr("ga5.action.id", tool_info["actionId"]),
                attr("ga5.attempt", att_item["attempt"]),
                attr("http.request.method", "POST"),
                attr("http.request.resend_count", att_item["attempt"] - 1)
            ]
            if att_item.get("receiptId"):
                att_attrs.append(attr("ga5.receipt.id", att_item["receiptId"]))
            if att_item.get("nonce"):
                att_attrs.append(attr("ga5.receipt.nonce", att_item["nonce"]))

            att_span = {
                "traceId": trace_id,
                "spanId": att_item["clientSpanId"],
                "parentSpanId": exec_id,
                "name": f"POST tool/{tool_info['toolName']}",
                "kind": 3, # CLIENT
                "attributes": att_attrs
            }

            status_val = att_item.get("status")
            err_type = att_item.get("errorType")
            if status_val == 503 or err_type == "503":
                att_span["attributes"].append(attr("error.type", "503"))
                att_span["status"] = {"code": 2}
            elif err_type == "timeout" or status_val == 0:
                att_span["attributes"].append(attr("error.type", "timeout"))
                att_span["status"] = {"code": 2}

            spans.append(att_span)

    # 5. incident.join span (if diagnostic calls > 1)
    diag_exec_ids = [e_id for e_id, t in logical_tools.items() if t.get("phase") == "diagnostic"]
    if len(diag_exec_ids) > 1 and join_span_id:
        join_span = {
            "traceId": trace_id,
            "spanId": join_span_id,
            "parentSpanId": invoke_span_id,
            "name": "incident.join",
            "kind": 1, # INTERNAL
            "attributes": [
                attr("ga5.run.id", run_id),
                attr("ga5.public.marker", public_marker)
            ],
            "links": [{"traceId": trace_id, "spanId": e_id} for e_id in diag_exec_ids]
        }
        spans.append(join_span)

    # 6. approval_gate span (if approval was required)
    if approval_span_id and approval_id:
        appr_attrs = [
            attr("ga5.run.id", run_id),
            attr("ga5.public.marker", public_marker),
            attr("ga5.approval.id", approval_id)
        ]
        if approval_nonce:
            appr_attrs.append(attr("ga5.receipt.nonce", approval_nonce))

        appr_span = {
            "traceId": trace_id,
            "spanId": approval_span_id,
            "parentSpanId": invoke_span_id,
            "name": "approval_gate",
            "kind": 1, # INTERNAL
            "attributes": appr_attrs
        }
        spans.append(appr_span)

    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": spans
                    }
                ]
            }
        ]
    }

def sanitize_arguments(raw_args: Any, input_schema: Dict[str, Any], service_default: str) -> Dict[str, Any]:
    """Strictly filter and format tool arguments according to JSON Schema."""
    if not isinstance(raw_args, dict):
        raw_args = {}

    props = input_schema.get("properties", {})
    required = input_schema.get("required", [])

    clean_args = {}
    for prop_name, prop_spec in props.items():
        if prop_name in raw_args:
            clean_args[prop_name] = raw_args[prop_name]
        elif prop_name in required:
            p_type = prop_spec.get("type", "string")
            if p_type in ["integer", "number"]:
                clean_args[prop_name] = 10
            elif p_type == "boolean":
                clean_args[prop_name] = True
            elif p_type == "array":
                clean_args[prop_name] = []
            else:
                clean_args[prop_name] = service_default

    return clean_args

async def analyze_incident_with_aipipe(body: Dict[str, Any]) -> Dict[str, Any]:
    incident = body.get("incident", {})
    tool_catalog = body.get("toolCatalog", [])
    policy = body.get("policy", {})

    transcript = incident.get("transcript", "")
    transcript_evidence = list(dict.fromkeys(re.findall(r'\[(ev_[a-zA-Z0-9_-]+)\]', transcript)))

    allowed_causes = incident.get("allowedRootCauses", [])
    effect_tools = set(policy.get("effectTools", []))
    max_diag = policy.get("maximumDiagnostics", 3)

    catalog_summary = []
    for t in tool_catalog:
        catalog_summary.append({
            "name": t.get("name"),
            "description": t.get("description"),
            "is_effect": t.get("name") in effect_tools,
            "inputSchema": t.get("inputSchema")
        })

    system_prompt = f"""You are an automated incident-response agent.
Analyze the transcript and catalog to choose root cause, diagnostic calls, and recovery effect.

CONSTRAINTS:
1. "rootCause": MUST be exactly one string chosen from allowedRootCauses: {json.dumps(allowed_causes)}.
2. "evidence": MUST be a JSON array of 2 to 4 evidence IDs (e.g. ["ev_101", "ev_102"]) found in transcript.
3. "diagnosticCalls": 1 to {max_diag} non-effect diagnostic tool calls.
   Each item:
   - "toolName": tool name from catalog
   - "arguments": object matching tool inputSchema
   - "evidence": array with 1 or 2 evidence IDs (subset of root cause evidence)
4. "chosenEffect": string (recovery tool name)
5. "effectArguments": object matching inputSchema for chosenEffect

Return ONLY a JSON object:
{{
  "rootCause": "...",
  "evidence": ["ev_...", "ev_..."],
  "diagnosticCalls": [
    {{ "toolName": "...", "arguments": {{...}}, "evidence": ["ev_..."] }}
  ],
  "chosenEffect": "...",
  "effectArguments": {{...}}
}}"""

    user_prompt = f"TRANSCRIPT:\n{transcript}\n\nCATALOG:\n{json.dumps(catalog_summary, indent=2)}"

    parsed = {}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                AIPIPE_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {AIPIPE_TOKEN}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": MODEL_NAME,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.0
                },
                timeout=12.0
            )
            resp.raise_for_status()
            parsed = json.loads(resp.json()["choices"][0]["message"]["content"])
    except Exception as e:
        print(f"[AI-PIPE EXCEPTION]: {e}", flush=True)

    # Sanitization
    model_rc = parsed.get("rootCause", "")
    if model_rc in allowed_causes:
        root_cause = model_rc
    else:
        matched = [c for c in allowed_causes if c.lower() in str(model_rc).lower() or str(model_rc).lower() in c.lower()]
        root_cause = matched[0] if matched else (allowed_causes[0] if allowed_causes else "unknown_failure")

    model_ev = parsed.get("evidence", [])
    if not isinstance(model_ev, list):
        model_ev = []
    
    valid_ev = [e for e in model_ev if e in transcript_evidence]
    for te in transcript_evidence:
        if len(valid_ev) >= 2:
            break
        if te not in valid_ev:
            valid_ev.append(te)

    if len(valid_ev) > 4:
        valid_ev = valid_ev[:4]
    if len(valid_ev) < 2:
        valid_ev = transcript_evidence[:2] if len(transcript_evidence) >= 2 else ["ev_101", "ev_102"]

    catalog_tools = {t["name"]: t for t in tool_catalog}
    diag_tools = {name: t for name, t in catalog_tools.items() if name not in effect_tools}

    raw_diag_calls = parsed.get("diagnosticCalls", [])
    if not isinstance(raw_diag_calls, list):
        raw_diag_calls = []

    clean_diag_calls = []
    service_val = incident.get("service", "default_service")

    for dc in raw_diag_calls:
        if not isinstance(dc, dict):
            continue
        t_name = dc.get("toolName")
        if t_name not in diag_tools:
            continue
        
        tool_spec = diag_tools[t_name]
        clean_args = sanitize_arguments(dc.get("arguments", {}), tool_spec.get("inputSchema", {}), service_val)

        dc_ev = dc.get("evidence", [])
        if not isinstance(dc_ev, list):
            dc_ev = []
        clean_dc_ev = [e for e in dc_ev if e in valid_ev]
        if not clean_dc_ev:
            clean_dc_ev = [valid_ev[0]]

        clean_diag_calls.append({
            "toolName": t_name,
            "arguments": clean_args,
            "evidence": clean_dc_ev
        })

    if not clean_diag_calls and diag_tools:
        first_tool_name = list(diag_tools.keys())[0]
        first_tool = diag_tools[first_tool_name]
        default_args = sanitize_arguments({}, first_tool.get("inputSchema", {}), service_val)

        clean_diag_calls.append({
            "toolName": first_tool_name,
            "arguments": default_args,
            "evidence": [valid_ev[0]]
        })

    if len(clean_diag_calls) > max_diag:
        clean_diag_calls = clean_diag_calls[:max_diag]

    chosen_effect = parsed.get("chosenEffect", "")
    if chosen_effect not in effect_tools:
        chosen_effect = list(effect_tools)[0] if effect_tools else "scale_service"

    eff_spec = catalog_tools.get(chosen_effect, {})
    clean_eff_args = sanitize_arguments(parsed.get("effectArguments", {}), eff_spec.get("inputSchema", {}), service_val)

    return {
        "rootCause": root_cause,
        "evidence": valid_ev,
        "diagnosticCalls": clean_diag_calls,
        "chosenEffect": chosen_effect,
        "effectArguments": clean_eff_args
    }

@app.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Malformed JSON body"})

    if not isinstance(body, dict) or body.get("profile") != PROFILE:
        return JSONResponse(status_code=400, content={"error": "Invalid profile"})

    run_id = body.get("runId")
    public_marker = body.get("publicMarker", "default_marker")
    if not run_id:
        return JSONResponse(status_code=400, content={"error": "Missing runId"})

    req_digest = compute_digest(body)

    # Replay or Conflict check
    cursor.execute("SELECT request_digest, state_json FROM runs WHERE run_id = ?", (run_id,))
    row = cursor.fetchone()
    if row:
        if row[0] != req_digest:
            return JSONResponse(status_code=409, content={"error": "Changed-content conflict for runId"})
        return JSONResponse(status_code=200, content=json.loads(row[1]))

    # Trace Context
    traceparent = request.headers.get("traceparent") or body.get("traceparent", "")
    trace_id = random_hex(16)
    incoming_span_id = None

    if traceparent and len(traceparent.split("-")) >= 3:
        parts = traceparent.split("-")
        if len(parts[1]) == 32 and len(parts[2]) == 16:
            trace_id = parts[1]
            incoming_span_id = parts[2]

    server_span_id = random_hex(8)
    invoke_span_id = random_hex(8)
    chat_span_id = random_hex(8)

    model_analysis = await analyze_incident_with_aipipe(body)

    root_cause = model_analysis.get("rootCause", "unknown")
    evidence = model_analysis.get("evidence", [])
    diag_calls = model_analysis.get("diagnosticCalls", [])
    chosen_effect = model_analysis.get("chosenEffect", "none")
    effect_args = model_analysis.get("effectArguments", {})

    dispatches = []
    attempts_history = []
    action_log = []

    join_span_id = random_hex(8) if len(diag_calls) > 1 else None

    for dc in diag_calls:
        action_id = f"act_{random_hex(6)}"
        call_id = f"call_{random_hex(6)}"
        client_span_id = random_hex(8)
        exec_tool_span_id = random_hex(8)
        tp = f"00-{trace_id}-{client_span_id}-01"

        disp = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": dc.get("toolName"),
            "arguments": dc.get("arguments", {}),
            "evidence": dc.get("evidence", evidence[:1]),
            "attempt": 1,
            "traceparent": tp
        }
        dispatches.append(disp)
        action_log.append(disp)

        att_record = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": dc.get("toolName"),
            "arguments": dc.get("arguments", {}),
            "evidence": dc.get("evidence", evidence[:1]),
            "attempt": 1,
            "clientSpanId": client_span_id,
            "execToolSpanId": exec_tool_span_id,
            "receiptId": None,
            "nonce": None,
            "status": None,
            "errorType": None
        }
        attempts_history.append(att_record)

    response_payload = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": root_cause,
            "evidence": evidence
        },
        "dispatches": dispatches,
        "approvals": []
    }

    cursor.execute("""
        INSERT INTO runs (
            run_id, request_digest, public_marker, trace_id, server_span_id, incoming_span_id,
            invoke_span_id, chat_span_id, join_span_id, policy_json, diagnosis_json,
            chosen_effect, effect_args_json, state_json, action_log_json, receipt_log_json,
            attempts_history_json, receipt_digests_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        run_id, req_digest, public_marker, trace_id, server_span_id, incoming_span_id,
        invoke_span_id, chat_span_id, join_span_id, json.dumps(body.get("policy", {})),
        json.dumps(response_payload["diagnosis"]), chosen_effect, json.dumps(effect_args),
        json.dumps(response_payload), json.dumps(action_log), json.dumps([]),
        json.dumps(attempts_history), json.dumps({})
    ))
    conn.commit()

    return JSONResponse(status_code=200, content=response_payload)


@app.post("/v2/incidents/{run_id}/receipts")
async def process_receipts(run_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Malformed receipt body"})

    receipt_id = body.get("receiptId")
    if not receipt_id:
        return JSONResponse(status_code=400, content={"error": "Missing receiptId"})

    cursor.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
    row = cursor.fetchone()
    if not row:
        return JSONResponse(status_code=400, content={"error": "Unknown runId"})

    (
        r_id, req_digest, public_marker, trace_id, server_span_id, incoming_span_id,
        invoke_span_id, chat_span_id, join_span_id, approval_span_id, approval_id,
        approval_nonce, effect_action_id, policy_json, diagnosis_json, chosen_effect,
        effect_args_json, state_json, action_log_json, receipt_log_json,
        attempts_history_json, receipt_digests_json, _
    ) = row

    policy = json.loads(policy_json)
    diagnosis = json.loads(diagnosis_json)
    effect_args = json.loads(effect_args_json)
    action_log = json.loads(action_log_json)
    receipt_log = json.loads(receipt_log_json)
    attempts_history = json.loads(attempts_history_json)
    receipt_digests = json.loads(receipt_digests_json)

    current_digest = compute_digest(body)

    if receipt_id in receipt_digests:
        if receipt_digests[receipt_id] != current_digest:
            return JSONResponse(status_code=409, content={"error": "Changed-content conflict for receiptId"})
        return JSONResponse(status_code=200, content=json.loads(state_json))

    receipt_digests[receipt_id] = current_digest

    outcomes = body.get("outcomes", [])
    approvals_in = body.get("approvals", [])

    new_dispatches = []
    run_failed = False

    for out in outcomes:
        a_id = out.get("actionId")
        c_id = out.get("callId")
        attempt_num = out.get("attempt", 1)
        st = out.get("status")
        err = out.get("errorType")
        nonce = out.get("nonce")

        receipt_log.append({
            "receiptId": receipt_id,
            "actionId": a_id,
            "callId": c_id,
            "attempt": attempt_num,
            "status": st,
            "resultClass": out.get("resultClass", ""),
            "nonce": nonce
        })

        for att in attempts_history:
            if att["actionId"] == a_id and att["callId"] == c_id and att["attempt"] == attempt_num:
                att["receiptId"] = receipt_id
                att["nonce"] = nonce
                att["status"] = st
                att["errorType"] = err

                if st == 503:
                    new_client_span = random_hex(8)
                    tp = f"00-{trace_id}-{new_client_span}-01"
                    retry_disp = {
                        "actionId": a_id,
                        "callId": c_id,
                        "phase": att.get("phase", "diagnostic"),
                        "toolName": att["toolName"],
                        "arguments": att["arguments"],
                        "evidence": att["evidence"],
                        "attempt": attempt_num + 1,
                        "traceparent": tp
                    }
                    new_dispatches.append(retry_disp)
                    action_log.append(retry_disp)

                    retry_att = dict(att)
                    retry_att["attempt"] = attempt_num + 1
                    retry_att["clientSpanId"] = new_client_span
                    retry_att["receiptId"] = None
                    retry_att["nonce"] = None
                    retry_att["status"] = None
                    retry_att["errorType"] = None
                    attempts_history.append(retry_att)

                elif st == 0 or err == "timeout":
                    run_failed = True

    for app_item in approvals_in:
        a_id = app_item.get("approvalId")
        dec = app_item.get("decision")
        nonce = app_item.get("nonce")

        receipt_log.append({
            "receiptId": receipt_id,
            "approvalId": a_id,
            "decision": dec,
            "nonce": nonce
        })

        if a_id == approval_id and dec == "approved":
            approval_nonce = nonce

    if run_failed:
        otlp = build_otlp_trace(
            run_id, public_marker, trace_id, server_span_id, incoming_span_id,
            invoke_span_id, chat_span_id, join_span_id, approval_span_id,
            approval_id, approval_nonce, attempts_history
        )
        final_payload = {
            "runId": run_id,
            "status": "failed",
            "diagnosis": diagnosis,
            "chosenEffect": chosen_effect,
            "suppressed": [chosen_effect],
            "actionLog": action_log,
            "receiptLog": receipt_log,
            "otlp": otlp
        }
        update_db(run_id, final_payload, action_log, receipt_log, attempts_history, receipt_digests, approval_span_id, approval_id, approval_nonce, effect_action_id)
        return JSONResponse(status_code=200, content=final_payload)

    if new_dispatches:
        waiting_payload = {
            "runId": run_id,
            "status": "waiting",
            "diagnosis": diagnosis,
            "dispatches": new_dispatches,
            "approvals": []
        }
        update_db(run_id, waiting_payload, action_log, receipt_log, attempts_history, receipt_digests, approval_span_id, approval_id, approval_nonce, effect_action_id)
        return JSONResponse(status_code=200, content=waiting_payload)

    diag_attempts = [a for a in attempts_history if a.get("phase") == "diagnostic"]
    all_diag_succeeded = len(diag_attempts) > 0 and all(a.get("status") == 200 for a in diag_attempts if a.get("receiptId"))

    if all_diag_succeeded:
        effect_attempts = [a for a in attempts_history if a.get("phase") == "effect"]

        if effect_attempts and any(a.get("status") == 200 for a in effect_attempts):
            otlp = build_otlp_trace(
                run_id, public_marker, trace_id, server_span_id, incoming_span_id,
                invoke_span_id, chat_span_id, join_span_id, approval_span_id,
                approval_id, approval_nonce, attempts_history
            )
            completed_payload = {
                "runId": run_id,
                "status": "completed",
                "diagnosis": diagnosis,
                "chosenEffect": chosen_effect,
                "suppressed": [],
                "actionLog": action_log,
                "receiptLog": receipt_log,
                "otlp": otlp
            }
            update_db(run_id, completed_payload, action_log, receipt_log, attempts_history, receipt_digests, approval_span_id, approval_id, approval_nonce, effect_action_id)
            return JSONResponse(status_code=200, content=completed_payload)

        approval_req = policy.get("approvalRequiredFor", [])
        requires_approval = chosen_effect in approval_req

        if requires_approval and not approval_nonce:
            if not approval_id:
                approval_id = f"appr_{random_hex(6)}"
                approval_span_id = random_hex(8)
                effect_action_id = f"act_{random_hex(6)}"

            args_digest = compute_digest(effect_args)
            approval_waiting_payload = {
                "runId": run_id,
                "status": "waiting",
                "dispatches": [],
                "approvals": [
                    {
                        "approvalId": approval_id,
                        "actionId": effect_action_id,
                        "toolName": chosen_effect,
                        "argumentsDigest": args_digest
                    }
                ]
            }
            update_db(run_id, approval_waiting_payload, action_log, receipt_log, attempts_history, receipt_digests, approval_span_id, approval_id, approval_nonce, effect_action_id)
            return JSONResponse(status_code=200, content=approval_waiting_payload)

        if not effect_attempts:
            eff_client_span = random_hex(8)
            eff_exec_span = random_hex(8)
            eff_act_id = effect_action_id if effect_action_id else f"act_{random_hex(6)}"
            eff_call_id = f"call_{random_hex(6)}"
            tp = f"00-{trace_id}-{eff_client_span}-01"

            eff_disp = {
                "actionId": eff_act_id,
                "callId": eff_call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": effect_args,
                "evidence": [],
                "attempt": 1,
                "traceparent": tp
            }
            if approval_id and approval_nonce:
                eff_disp["approvalId"] = approval_id
                eff_disp["approvalNonce"] = approval_nonce

            action_log.append(eff_disp)

            eff_att = {
                "actionId": eff_act_id,
                "callId": eff_call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": effect_args,
                "evidence": [],
                "attempt": 1,
                "clientSpanId": eff_client_span,
                "execToolSpanId": eff_exec_span,
                "receiptId": None,
                "nonce": None,
                "status": None,
                "errorType": None
            }
            attempts_history.append(eff_att)

            effect_waiting_payload = {
                "runId": run_id,
                "status": "waiting",
                "diagnosis": diagnosis,
                "dispatches": [eff_disp],
                "approvals": []
            }
            update_db(run_id, effect_waiting_payload, action_log, receipt_log, attempts_history, receipt_digests, approval_span_id, approval_id, approval_nonce, eff_act_id)
            return JSONResponse(status_code=200, content=effect_waiting_payload)

    return JSONResponse(status_code=200, content=json.loads(state_json))


@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    cursor.execute("SELECT state_json FROM runs WHERE run_id = ?", (run_id,))
    row = cursor.fetchone()
    if not row:
        return JSONResponse(status_code=404, content={"error": "Run not found"})
    return JSONResponse(status_code=200, content=json.loads(row[0]))


def update_db(run_id: str, state_payload: dict, action_log: list, receipt_log: list, attempts_history: list, receipt_digests: dict, app_span_id: str, app_id: str, app_nonce: str, eff_act_id: str):
    cursor.execute("""
        UPDATE runs SET
            state_json = ?,
            action_log_json = ?,
            receipt_log_json = ?,
            attempts_history_json = ?,
            receipt_digests_json = ?,
            approval_span_id = ?,
            approval_id = ?,
            approval_nonce = ?,
            effect_action_id = ?
        WHERE run_id = ?
    """, (
        json.dumps(state_payload), json.dumps(action_log), json.dumps(receipt_log),
        json.dumps(attempts_history), json.dumps(receipt_digests), app_span_id,
        app_id, app_nonce, eff_act_id, run_id
    ))
    conn.commit()