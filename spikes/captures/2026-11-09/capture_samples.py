import asyncio, json, sys
from nearai_inference_sdk import InferenceClient
from familybox import pinning
MODEL="deepseek-ai/DeepSeek-V4.1-Flash-1017"
async def one():
    rows=[]
    ql=pinning.QuoteLog()
    async def gw(dep): rows.append(("gateway", dep))
    async def md(model, dep): rows.append(("model", dep))
    from nearai_inference_sdk import AttestationVerifiers, GatewayVerificationOptions, ModelAttestationVerifiers, ModelVerificationOptions
    async with InferenceClient(None, attestation_cache_time_to_live_ms=0,
        gateway_verification=GatewayVerificationOptions(verifiers=AttestationVerifiers(tdx_quote=ql, deployment=gw)),
        model_verification=ModelVerificationOptions(verifiers=ModelAttestationVerifiers(tdx_quote=ql)), deployment_policy=md) as c:
        r = await c.verify(MODEL)
    out=[]
    for kind, dep in rows:
        for m in pinning.measure(kind, MODEL, dep, ql.lookup(dep.app_compose)):
            out.append({"c": m.component, "fp": m.fp, "fields": m.fields, "info": m.info, "signer": None})
    out.append({"signers": [r.gateway.signer.signing_address] + [x.signer.signing_address for x in r.models], "tcb": [r.gateway.tcb_status]+[x.tcb_status for x in r.models]})
    return out
async def main():
    res=[]
    for i in range(int(sys.argv[2])):
        res.append(await one()); await asyncio.sleep(3)
    json.dump(res, open(sys.argv[1],"w"), indent=1)
asyncio.run(main())
