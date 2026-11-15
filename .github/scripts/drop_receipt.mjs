/** Spec #87: seal a Cloudflare bearer claim URL before any OIDC callback or D1 write.
 * Never write plaintext or the sealed envelope to the GitHub log/output.
 */
import {constants, createCipheriv, publicEncrypt, randomBytes} from 'node:crypto';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const PREVIEW=/^https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+workers\.dev\/?$/;
const TOKEN=/^[A-Za-z0-9_-]{16,1024}$/;
export class DropReceiptError extends Error{
  constructor(){super('drop_receipt_invalid');this.name='DropReceiptError';}
}
export function validateDropClaim({attemptId,previewUrl,claimUrl,expiresAt},now=Date.now()){
  try{
    if(!UUID.test(attemptId)||typeof previewUrl!=='string'||previewUrl.length>240||
       !PREVIEW.test(previewUrl)||!Number.isSafeInteger(expiresAt)||
       !Number.isSafeInteger(now)||expiresAt<=now||expiresAt>now+3600000)
       throw new Error();
    const url=new URL(claimUrl);
    if(url.protocol!=='https:'||url.hostname!=='dash.cloudflare.com'||
       url.port||url.username||url.password||url.pathname!=='/claim-preview'||
       url.hash||[...url.searchParams.keys()].join(',')!=='claimToken'||
       !TOKEN.test(url.searchParams.get('claimToken')||''))
       throw new Error();
    return {attemptId:attemptId.toLowerCase(),previewUrl,claimUrl,expiresAt};
  }catch{throw new DropReceiptError();}
}
export function sealDropClaim(input,publicKey,{now=Date.now()}={}){
  try{
    const value=validateDropClaim(input,now);
    if(typeof publicKey!=='string'||publicKey.length>8000)throw new DropReceiptError();
    const aes=randomBytes(32),iv=randomBytes(12);
    const aad=Buffer.from('drop-receipt-v1\n'+value.attemptId+'\n'+value.previewUrl+'\n'+value.expiresAt);
    const cipher=createCipheriv('aes-256-gcm',aes,iv);
    cipher.setAAD(aad);
    const ciphertext=Buffer.concat([
      cipher.update(JSON.stringify({claimUrl:value.claimUrl,attemptId:value.attemptId,
        previewUrl:value.previewUrl,expiresAt:value.expiresAt}),'utf8'),
      cipher.final(),cipher.getAuthTag()]);
    const wrapped=publicEncrypt({key:publicKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},aes);
    const sealed=Buffer.from(JSON.stringify({v:1,wrapped_key:wrapped.toString('base64url'),
      nonce:iv.toString('base64url'),ciphertext:ciphertext.toString('base64url')})).toString('base64url');
    if(sealed.length>3600)throw new DropReceiptError();
    return {drop_claim_v:1,preview_url:value.previewUrl,expires_at:value.expiresAt,sealed_claim:sealed};
  }catch{throw new DropReceiptError();}
}
