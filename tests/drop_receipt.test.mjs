import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,constants,privateDecrypt,createDecipheriv} from 'node:crypto';
import {sealDropClaim,DropReceiptError} from '../.github/scripts/drop_receipt.mjs';
import {submitSealedDropResult,deliverDropClaim} from '../.github/scripts/drop_runner.mjs';

const id='11111111-2222-4333-8444-555555555555';
const url='https://dash.cloudflare.com/claim-preview?claimToken='+('x'.repeat(48));
const preview='https://test-preview.workers.dev';
const now=1800000000000;
const keys=generateKeyPairSync('rsa',{modulusLength:2048,
  publicKeyEncoding:{format:'pem',type:'spki'},
  privateKeyEncoding:{format:'pem',type:'pkcs8'}});
const input={attemptId:id,claimUrl:url,previewUrl:preview,expiresAt:now+3000000};

test('G4 reverse envelope: authenticates Attempt, preview, expiry and hides claim',()=>{
 const receipt=sealDropClaim(input,keys.publicKey,{now});
 assert.equal(receipt.drop_claim_v,1);
 assert.equal(receipt.preview_url,preview);
 assert.equal(receipt.expires_at,input.expiresAt);
 assert.ok(receipt.sealed_claim.length<3600);
 assert.ok(!JSON.stringify(receipt).includes('claim-preview'));
 assert.ok(!JSON.stringify(receipt).includes('claimToken'));
 const envelope=JSON.parse(Buffer.from(receipt.sealed_claim,'base64url').toString('utf8'));
 const secret=privateDecrypt({key:keys.privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash:'sha256'},Buffer.from(envelope.wrapped_key,'base64url'));
 const ciphertext=Buffer.from(envelope.ciphertext,'base64url');
 const decrypter=createDecipheriv('aes-256-gcm',secret,Buffer.from(envelope.nonce,'base64url'));
 decrypter.setAAD(Buffer.from('drop-receipt-v1\n'+id+'\n'+preview+'\n'+input.expiresAt));
 decrypter.setAuthTag(ciphertext.subarray(-16));
 const output=JSON.parse(Buffer.concat([
  decrypter.update(ciphertext.subarray(0,-16)),decrypter.final()
 ]).toString('utf8'));
 assert.deepEqual(output,{claimUrl:url,attemptId:id,previewUrl:preview,expiresAt:input.expiresAt});
});
test('G4 rejects unapproved claim domains, tokens, attempts and expiration',()=>{
 for(const bad of [
  {...input,claimUrl:url.replace('dash.cloudflare.com','evil.invalid')},
  {...input,claimUrl:url+'&redirect=https://evil.invalid'},
  {...input,claimUrl:url.replace('https://','http://')},
  {...input,previewUrl:'https://evil.invalid'},
  {...input,attemptId:'wrong-attempt'},
  {...input,expiresAt:now-1},
  {...input,expiresAt:now+3600001},
 ]){
  assert.throws(()=>sealDropClaim(bad,keys.publicKey,{now}),DropReceiptError);
 }
});
test('G4 signed-result subprocess receives only sealed stdin; no bearer in argv/env/log',()=>{
 const receipt=sealDropClaim(input,keys.publicKey,{now});
 let dispatched=0;
 const output=submitSealedDropResult(receipt,{
  ATTEMPT_ID:id,DISPATCH_ID:id,CAPABILITY_ID:'github.action',
  WORKFLOW_ACTION_CLAIM_URL:'https://workflow.example/github/action/claim',
  ACTIONS_ID_TOKEN_REQUEST_URL:'https://token.actions.githubusercontent.com',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN:'fixture-opaque',
 },{post:(executable,args,options)=>{
  dispatched++;
  assert.equal(executable,'python3');
  assert.equal(args.length,1);
  assert.ok(args[0].endsWith('/drop_result.py'));
  assert.deepEqual(JSON.parse(options.input),receipt);
  assert.ok(!JSON.stringify(args).includes('claimToken'));
  assert.ok(!JSON.stringify(options.env).includes('claimToken'));
  return {status:0,error:null,stdout:'',stderr:''};
 }});
 assert.equal(dispatched,1);
 assert.equal(output.status,'drop_receipt_acknowledged');
 assert.throws(()=>submitSealedDropResult({...receipt,sealed_claim:''},{},
  {post:()=>{throw Error('should not run');}}),/drop_receipt_invalid/);
});

test('G4 callback composite seals before transport and never supplies bearer to subprocess',()=>{
 const current=Date.now();
 const actual={...input,expiresAt:current+1200000};
 let sends=0;
 const env={ATTEMPT_ID:id,DROP_RECEIPT_PUBLIC_KEY_PEM:keys.publicKey};
 const result=deliverDropClaim(actual,env,{post:(_exe,_argv,options)=>{
  sends++;
  assert.ok(!JSON.stringify(options).includes('claimToken'));
  const privateBody=JSON.parse(options.input);
  assert.ok(privateBody.sealed_claim.length>250);
  return {status:0};
 }});
 assert.equal(sends,1);
 assert.deepEqual(result,{status:'drop_receipt_acknowledged'});
});
