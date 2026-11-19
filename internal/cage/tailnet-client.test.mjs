import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createTailnetClient } from "./tailnet-client.mjs";

test("stdio requests are serialized, preserve component errors and reject wire commands", async () => {
  const seen = [];
  const fixture = `let text=''; process.stdin.on('data',chunk=>{text+=chunk;let end;while((end=text.indexOf('\\n'))>=0){const input=JSON.parse(text.slice(0,end));text=text.slice(end+1);setTimeout(()=>console.log(JSON.stringify(input.action==='add-key'?{error:'请粘贴有效 SSH 公钥'}:{installed:true,action:input.action})),10)}});`;
  const client = createTailnetClient({ executable: process.execPath, start: (file,args,options) => { seen.push({file,args}); return spawn(process.execPath, ["-e", fixture], options); } });
  try {
    const values = await Promise.all([client.request({action:"status"}), client.request({action:"connect"}), client.request({action:"add-key",key:"invalid"})]);
    assert.deepEqual(values.map(v=>v.action||v.tailnet_error), ["status","connect","请粘贴有效 SSH 公钥"]);
    assert.equal(seen.length,1);
    await assert.rejects(client.request({action:"shell",command:"whoami"}));
    await assert.rejects(client.request({action:"add-key",key:"x".repeat(8193)}));
    assert.equal((await client.request({action:"status"})).installed,true);
  } finally {client.close();}
});
test("missing guest payload offers installation without spawning a host VPN", async()=>{
 const client=createTailnetClient({executable:"/nonexistent-cage-tailnet",start:()=>{throw Error("must not spawn")}});
 assert.equal((await client.request({action:"status"})).installed,false);
});
test("control_url is forwarded, validated, and marked only on real responses", async () => {
  const client = createTailnetClient({ executable: process.execPath, start: (_file,_args,options) => spawn(process.execPath, ["-e", `let text='';process.stdin.on('data',chunk=>{text+=chunk;let end;while((end=text.indexOf('\\n'))>=0){const input=JSON.parse(text.slice(0,end));text=text.slice(end+1);if(input.action==='add-key'){console.log(JSON.stringify({error:'boom',control_url:''}));continue;}console.log(JSON.stringify(input));}});`], options) });
  try {
    const forwarded = await client.request({action:"control-server",control_url:"https://hs.example.com"});
    assert.equal(forwarded.control_url, "https://hs.example.com");
    assert.deepEqual(forwarded.capabilities, ["control-url"]);
    const empty = await client.request({action:"connect",control_url:""});
    assert.equal(empty.control_url, "");
    assert.deepEqual(empty.capabilities, ["control-url"]);
    const legacy = await client.request({action:"status"});
    assert.equal("control_url" in legacy, false);
    assert.equal("capabilities" in legacy, false);
    const failed = await client.request({action:"add-key",key:"x"});
    assert.equal(failed.tailnet_error, "boom");
    assert.equal("capabilities" in failed, false);
    await assert.rejects(client.request({action:"control-server"}));
    await assert.rejects(client.request({action:"connect",control_url:"http://hs.example.com"}));
    await assert.rejects(client.request({action:"connect",control_url:"https://hs.example.com/path"}));
    await assert.rejects(client.request({action:"connect",control_url:"https://user@hs.example.com"}));
    await assert.rejects(client.request({action:"connect",control_url:1}));
  } finally {client.close();}
});
test("missing guest payload does not echo control_url or capabilities", async()=>{
 const client=createTailnetClient({executable:"/nonexistent-cage-tailnet",start:()=>{throw Error("must not spawn")}});
 const value=await client.request({action:"control-server",control_url:"https://hs.example.com"});
 assert.equal(value.installed,false);
 assert.equal("control_url" in value, false);
 assert.equal("capabilities" in value, false);
});
test("service destinations are validated and forwarded through the same private protocol", async () => {
 const client = createTailnetClient({ executable: process.execPath, start: (_file,_args,options) => spawn(process.execPath, ["-e", `let text='';process.stdin.on('data',chunk=>{text+=chunk;let end;while((end=text.indexOf('\\n'))>=0){const input=JSON.parse(text.slice(0,end));text=text.slice(end+1);console.log(JSON.stringify(input))}});`], options) });
 try {
  const result = await client.request({action:"open-service",host:"100.88.2.4",port:8080,command:"ignored"});
  assert.deepEqual(result,{action:"open-service",host:"100.88.2.4",port:8080});
  for (const input of [{host:"100.88.2.4",port:0},{host:"100.88.2.4",port:65536},{host:"100.88.2.4",port:"80"},{host:"100.88.2.4\ncommand",port:80}]) await assert.rejects(client.request({action:"open-service",...input}));
  assert.equal((await client.request({action:"status"})).action,"status");
 } finally {client.close();}
});
