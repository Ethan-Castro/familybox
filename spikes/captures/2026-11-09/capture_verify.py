import asyncio, json, sys, time
from dataclasses import asdict, is_dataclass
from nearai_inference_sdk import InferenceClient
MODEL="deepseek-ai/DeepSeek-V4.1-Flash-1017"
def conv(o):
    if is_dataclass(o): return {k: conv(v) for k,v in asdict(o).items()}
    if isinstance(o, dict): return {k: conv(v) for k,v in o.items()}
    if isinstance(o,(list,tuple)): return [conv(x) for x in o]
    if isinstance(o, bytes): return o.hex()
    return o
async def main():
    async def pol(model, dep): pass
    async with InferenceClient(None, e2ee=False, deployment_policy=pol) as c:
        r = await c.verify(MODEL)
        json.dump(conv(r), open(sys.argv[1],"w"), indent=1, default=str)
asyncio.run(main())
