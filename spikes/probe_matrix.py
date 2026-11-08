import asyncio, os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from day1_tool_loop import TOOLS
from nearai_inference_sdk import InferenceClient, get_sdk_error
KEY = os.environ["NEAR_AI_CLOUD_API_KEY"]
MSG = [{"role": "user", "content": "Find Maya's passport expiry using the tools."}]
async def one(model, e2ee, tools):
    async with InferenceClient(KEY, e2ee=e2ee) as c:
        try:
            kw = dict(model=model, messages=MSG, stream=False, max_tokens=200)
            if tools: kw.update(tools=TOOLS, tool_choice="auto")
            r = await c.chat.completions.create(**kw)
            v = await c.verify_response(r.id)
            m = r.choices[0].message
            return f"ok sig={v.signature_kind} tool_calls={[t.function.name for t in (m.tool_calls or [])]}"
        except Exception as e:
            s = get_sdk_error(e); return "FAIL " + (s.failure.code if s else str(e)[:140])
async def main():
    for model in sys.argv[1:]:
        for e2ee, tools in [(True, False), (False, True), (True, True)]:
            print(f"{model:40s} e2ee={e2ee!s:5} tools={tools!s:5} ->", await one(model, e2ee, tools), flush=True)
asyncio.run(main())
