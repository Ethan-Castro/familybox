import asyncio, os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from day1_tool_loop import TOOLS, run_tool
from nearai_inference_sdk import InferenceClient, get_sdk_error
KEY = os.environ["NEAR_AI_CLOUD_API_KEY"]
async def two_turns(model, e2ee, content_none):
    async with InferenceClient(KEY, e2ee=e2ee) as c:
        msgs = [{"role": "user", "content": "When does Maya's passport expire? Use the tools."}]
        r = await c.chat.completions.create(model=model, messages=msgs, tools=TOOLS, stream=False, max_tokens=400)
        m = r.choices[0].message
        if not m.tool_calls: return "no tool call on turn 0"
        msgs.append({"role": "assistant", "content": None if content_none else (m.content or ""),
                     "tool_calls": [{"id": t.id, "type": "function", "function": {"name": t.function.name, "arguments": t.function.arguments}} for t in m.tool_calls]})
        for t in m.tool_calls:
            msgs.append({"role": "tool", "tool_call_id": t.id, "content": run_tool(t.function.name, json.loads(t.function.arguments or "{}"))})
        try:
            r2 = await c.chat.completions.create(model=model, messages=msgs, tools=TOOLS, stream=False, max_tokens=400)
            v = await c.verify_response(r2.id)
            m2 = r2.choices[0].message
            return f"ok sig={v.signature_kind} next={'tools '+str([t.function.name for t in m2.tool_calls]) if m2.tool_calls else 'answer: '+(m2.content or '')[:80]}"
        except Exception as e:
            s = get_sdk_error(e); return "FAIL " + (s.failure.code if s else str(e)[:120])
async def main():
    for model in ["z-ai/glm-5.3-flash", "deepseek-ai/DeepSeek-V4.1-Flash-1017"]:
        for e2ee, cn in [(False, False), (True, False), (True, True)]:
            print(f"{model:38s} e2ee={e2ee!s:5} content_none={cn!s:5} ->", await two_turns(model, e2ee, cn), flush=True)
asyncio.run(main())
