import asyncio
import json
import uuid
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

app = FastAPI()

# Global list of active SSE queues
ACTIVE_QUEUES = []
# Global list of active WebSockets
ACTIVE_WEBSOCKETS = []

# AUTH CONFIG
REQUIRED_TOKEN = "bearer-token-123"
REQUIRED_API_KEY = "secret-key-456"

# In-memory storage for discovered items
TOOLS = {
    "get_weather": {
        "description": "Get the current weather in a given location",
        "inputSchema": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "The city and state, e.g. San Francisco, CA"
                }
            },
            "required": ["location"]
        }
    },
    "echo_input": {
        "description": "Vulnerable tool: Echoes input directly (Simulated Injection)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": { "type": "string" }
            }
        }
    },
    "crash_me": {
        "description": "Vulnerable tool: Crashes on non-integer input (Type Confusion)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": { "type": "integer" }
            }
        }
    }
}

RESOURCES = {
    "user_data": {
        "uri": "file:///etc/passwd",
        "description": "A sample file resource URI.",
        "type": "text/plain"
    },
    "secure_logs_template": {
        "uri": "file:///logs/{id}",
        "description": "Vulnerable resource template",
        "type": "text/plain"
    },
    "latest_log": {
        "uri": "file:///logs/100",
        "description": "The most recent log file.",
        "type": "text/plain"
    }
}

PROMPTS = {
    "summarize_text": {
        "description": "Summarize the provided text.",
        "template": "Please summarize the following text: {text}"
    }
}

def verify_auth(request: Request):
    # Check for Bearer Token
    auth_header = request.headers.get("Authorization")
    if auth_header == f"Bearer {REQUIRED_TOKEN}":
        return True
    
    # Check for API Key
    api_key = request.headers.get("X-API-Key")
    if api_key == REQUIRED_API_KEY:
        return True
    
    return False

async def handle_mcp_request(request_data):
    method = request_data.get("method")
    params = request_data.get("params")
    request_id = request_data.get("id")

    response = {
        "jsonrpc": "2.0",
        "id": request_id,
    }

    if method == "initialize":
        print(f"DEBUG: Received initialization params: {params}")
        response["result"] = {"version": "0.1.0", "capabilities": {}}
        await broadcast_message(response)
        await asyncio.sleep(0.1)
        await broadcast_message({"jsonrpc": "2.0", "method": "initialized", "params": {}})
    elif method == "tools/list":
        response["result"] = TOOLS
        await broadcast_message(response)
    elif method == "resources/list":
        response["result"] = RESOURCES
        await broadcast_message(response)
    elif method == "prompts/list":
        response["result"] = PROMPTS
        await broadcast_message(response)
    elif method == "tools/invoke":
        tool_name = params.get("name")
        tool_params = params.get("arguments", {})
        if tool_name == "get_weather":
            response["result"] = {
                "status": "success",
                "output": f"Successfully invoked {tool_name} with parameters: {tool_params}"
            }
        elif tool_name == "echo_input":
            msg = tool_params.get("message", "")
            # Simulate a "vulnerable" reflection
            response["result"] = { "echo": msg }
        elif tool_name == "crash_me":
            code = tool_params.get("code")
            if not isinstance(code, int):
                # Simulate a crash or leak
                response["error"] = {
                    "code": -32603,
                    "message": "Internal error: Expected int, got " + str(type(code)),
                    "data": "Stacktrace: ... at mcp_server.py:120"
                }
            else:
                response["result"] = { "status": "ok", "code": code }
        else:
            response["error"] = {"code": -32601, "message": "Method not found"}
        await broadcast_message(response)
    elif method == "resources/read":
        uri = params.get("uri")
        if uri == "file:///etc/passwd":
            response["result"] = {
                "contents": [{
                    "uri": uri,
                    "mimeType": "text/plain",
                    "text": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:..."
                }]
            }
        elif "file:///logs/" in uri:
            # Vulnerable BOLA logic: Accepts any ID
            try:
                log_id = uri.split("/")[-1]
                response["result"] = {
                    "contents": [{
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": f"Confidential Log Entry #{log_id}: System crashed at..."
                    }]
                }
            except:
                response["error"] = {"code": -32602, "message": "Invalid URI"}
        else:
             response["error"] = {"code": -32602, "message": "Resource not found"}
        await broadcast_message(response)
    else:
        response["error"] = {"code": -32601, "message": "Method not found"}
        await broadcast_message(response)

async def broadcast_message(message):
    data = json.dumps(message)
    print(f"DEBUG: Broadcasting message: {data}")
    
    # Broadcast to SSE
    for i, queue in enumerate(list(ACTIVE_QUEUES)):
        await queue.put(data)

    # Broadcast to WebSockets
    for i, ws in enumerate(list(ACTIVE_WEBSOCKETS)):
        try:
            await ws.send_text(data)
        except Exception as e:
            if ws in ACTIVE_WEBSOCKETS:
                ACTIVE_WEBSOCKETS.remove(ws)

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Check headers in handshake
    auth_header = websocket.headers.get("Authorization")
    api_key = websocket.headers.get("X-API-Key")
    
    if auth_header != f"Bearer {REQUIRED_TOKEN}" and api_key != REQUIRED_API_KEY:
        print("DEBUG: WS Auth Failed")
        await websocket.close(code=1008)
        return

    await websocket.accept()
    ACTIVE_WEBSOCKETS.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                request_data = json.loads(data)
                await handle_mcp_request(request_data)
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    finally:
        if websocket in ACTIVE_WEBSOCKETS:
            ACTIVE_WEBSOCKETS.remove(websocket)

# SSE endpoint - ESTABLISHES CONNECTION
@app.get("/mcp")
async def mcp_sse_endpoint(request: Request):
    if not verify_auth(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    sse_queue = asyncio.Queue()
    ACTIVE_QUEUES.append(sse_queue)

    async def event_generator():
        try:
            while True:
                message = await sse_queue.get()
                yield {"event": "message", "data": message}
        except asyncio.CancelledError:
            if sse_queue in ACTIVE_QUEUES:
                ACTIVE_QUEUES.remove(sse_queue)

    return EventSourceResponse(event_generator())

# POST endpoint - RECEIVES MESSAGES
@app.post("/mcp")
async def mcp_post_endpoint(request: Request):
    if not verify_auth(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode('utf-8')
        request_data = json.loads(body_str)
        if isinstance(request_data, list):
            for item in request_data:
                await handle_mcp_request(item)
        else:
            await handle_mcp_request(request_data)
        return JSONResponse({"status": "accepted"})
    except Exception as e:
         return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
