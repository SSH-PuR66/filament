"use strict";
const assert = require("node:assert/strict");
const model = require("./install_flow.js");
const state = {device:{present:true,udid:"test-device",version:"26.6",connection:"USB"},devmode:{enabled:true}};
const input = {app:"C:\\Apps\\test.ipa",use_identity:true};
let cases = 0;
function test(name, fn) { fn(); cases++; console.log("PASS " + name); }
function fresh() { const gate = model.createGate(); gate.observe(state, 1000); return gate; }
function approve(gate) { const ticket = gate.begin(input, 1000); assert.equal(gate.finish(ticket,true,input,1100),true); }

test("install requires a successful app preflight", () => {
  const gate = fresh(); assert.equal(gate.canInstall(input,1100),false); approve(gate);
  assert.equal(gate.canInstall(input,1200),true);
});
test("changing the IPA invalidates a prior check", () => {
  const gate = fresh(); approve(gate);
  assert.equal(gate.canInstall({...input,app:"different.ipa"},1200),false);
});
test("identity changes cannot reuse the configured check", () => {
  const gate = fresh(); approve(gate);
  assert.equal(gate.canInstall({...input,use_identity:false},1200),false);
});
test("custom paths and exact password bytes are part of the check", () => {
  for (const field of ["profile","p12","p12password"]) {
    const original={app:"test.ipa",use_identity:false,profile:"test.profile",p12:"test.p12",p12password:" secret "};
    const gate=fresh(),ticket=gate.begin(original,1000);gate.finish(ticket,true,original,1100);
    assert.equal(gate.canInstall({...original,[field]:"different"},1200),false);
  }
});
test("failed and mistyped responses never unlock install", () => {
  for (const ok of [false,"true",1,null]) {
    const gate=fresh(),ticket=gate.begin(input,1000);
    assert.equal(gate.finish(ticket,ok,input,1100),false);
  }
});
test("an old response cannot approve a newer request", () => {
  const gate=fresh(),old=gate.begin(input,1000),current=gate.begin(input,1001);
  assert.equal(gate.finish(old,true,input,1100),false);
  assert.equal(gate.finish(current,true,input,1101),true);
});
test("input event invalidation rejects an in-flight response even after reverting", () => {
  const gate=fresh(),ticket=gate.begin(input,1000);gate.invalidate();
  assert.equal(gate.finish(ticket,true,input,1100),false);
});
test("disconnect or daemon failure invalidates the check", () => {
  for (const disconnected of [null,{}, {device:{present:false}}]) {
    const gate=fresh();approve(gate);gate.observe(disconnected,1200);
    assert.equal(gate.canInstall(input,1200),false);
    gate.observe(state,1300);assert.equal(gate.canInstall(input,1300),false);
  }
});
test("switching devices, OS version, or Developer Mode invalidates the check", () => {
  for (const changed of [{...state,device:{...state.device,udid:"another-device"}},
    {...state,device:{...state.device,version:"26.7"}}, {...state,devmode:{enabled:false}}]) {
    const gate=fresh();approve(gate);gate.observe(changed,1200);
    assert.equal(gate.canInstall(input,1200),false);
  }
});
test("fresh repeated observations preserve an unchanged check", () => {
  const gate=fresh();approve(gate);gate.observe(state,1200);
  assert.equal(gate.canInstall(input,1300),true);
});
test("stale device evidence and an expired check disable installation", () => {
  const gate=fresh();approve(gate);
  assert.equal(gate.canInstall(input,17000),false);
  gate.observe(state,122000);assert.equal(gate.canInstall(input,122001),false);
});
test("a slow result with stale device evidence requires another check", () => {
  const gate=fresh(),ticket=gate.begin(input,1000);
  assert.equal(gate.finish(ticket,true,input,17000),false);
});
test("clock rollback never extends a check", () => {
  const gate=fresh();approve(gate);assert.equal(gate.canInstall(input,999),false);
});
test("device presence without identity is insufficient", () => {
  const gate=model.createGate();gate.observe({device:{present:true}},1000);
  const ticket=gate.begin(input,1000);assert.equal(gate.finish(ticket,true,input,1100),false);
});
test("unknown, disconnected and blocked setup remain distinct", () => {
  assert.deepEqual(model.setup(null,null).map(x=>x.status),["unknown","waiting","unknown"]);
  assert.deepEqual(model.setup({device:{present:false}},null).map(x=>x.status),["action","waiting","unknown"]);
  assert.equal(model.setup(state,{ready:false,blockers:["profile expired"]})[2].detail,"profile expired");
});
test("iOS 15 has no Developer Mode switch", () => {
  assert.equal(model.setup({...state,device:{...state.device,version:"15.8.6"},devmode:{}},null)[1].status,"ready");
  assert.equal(model.setup({...state,devmode:{}},null)[1].status,"unknown");
});
console.log(`${cases} install-flow cases passed`);
