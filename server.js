// Transmissor Nota Fácil → NFS-e Nacional.
// Recebe a DPS montada pelo app, assina (XMLDSig RSA-SHA256) e envia por mTLS com o certificado A1.
import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import forge from "node-forge";
import { SignedXml } from "xml-crypto";

const TOKEN = process.env.TRANSMISSOR_TOKEN;
const PORT = Number(process.env.PORT || 3000);
const BASES = {
  1: "https://sefin.nfse.gov.br/SefinNacional",
  2: "https://sefin.producaorestrita.nfse.gov.br/SefinNacional",
};
if (!process.env.NO_SERVER && (!TOKEN || TOKEN.length < 24)) { console.error("Defina TRANSMISSOR_TOKEN (mínimo 24 caracteres)"); process.exit(1); }

function abrirPfx(pfxB64, senha) {
  const der = forge.util.decode64(pfxB64);
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(der), false, senha);
  const kOid = forge.pki.oids.pkcs8ShroudedKeyBag, cOid = forge.pki.oids.certBag;
  const key = (p12.getBags({ bagType: kOid })[kOid] ?? [])[0]?.key
    ?? (p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ?? [])[0]?.key;
  const certs = (p12.getBags({ bagType: cOid })[cOid] ?? []).map((b) => b.cert);
  if (!key || !certs.length) throw new Error("Certificado sem chave privada");
  const pubMod = forge.pki.setRsaPublicKey(key.n, key.e).n.toString(16);
  const cert = certs.find((c) => c.publicKey.n.toString(16) === pubMod) ?? certs[0];
  return { keyPem: forge.pki.privateKeyToPem(key), certPem: forge.pki.certificateToPem(cert), validade: cert.validity.notAfter };
}

function assinar(xml, keyPem, certPem, elemento = "infDPS") {
  const certB64 = certPem.replace(/-----[^-]+-----|\s/g, "");
  const sig = new SignedXml({
    privateKey: keyPem,
    publicCert: certPem,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    getKeyInfoContent: () => `<X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`,
  });
  sig.addReference({
    xpath: `//*[local-name(.)='${elemento}']`,
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  sig.computeSignature(xml, { location: { reference: `//*[local-name(.)='${elemento}']`, action: "after" } });
  return sig.getSignedXml();
}

function chamar(metodo, url, corpo, keyPem, certPem) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method: metodo, key: keyPem, cert: certPem, timeout: 60000,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
    }, (res) => {
      let dados = ""; res.setEncoding("utf8");
      res.on("data", (c) => (dados += c));
      res.on("end", () => { let json; try { json = JSON.parse(dados); } catch { json = { bruto: dados }; } resolve({ status: res.statusCode, json }); });
    });
    req.on("timeout", () => req.destroy(new Error("Tempo esgotado ao falar com o sistema nacional")));
    req.on("error", reject);
    if (corpo) req.write(JSON.stringify(corpo));
    req.end();
  });
}

const gunzipB64 = (b64) => zlib.gunzipSync(Buffer.from(b64, "base64")).toString("utf8");

async function emitir({ pfxB64, senha, xml, ambiente, idDps }) {
  const base = BASES[ambiente];
  if (!base) throw new Error("Ambiente inválido");
  const { keyPem, certPem, validade } = abrirPfx(pfxB64, senha);
  if (validade < new Date()) throw new Error("Certificado digital vencido");
  const assinado = assinar(xml, keyPem, certPem);
  const dpsXmlGZipB64 = zlib.gzipSync(Buffer.from(assinado, "utf8")).toString("base64");
  let r;
  try { r = await chamar("POST", `${base}/nfse`, { dpsXmlGZipB64 }, keyPem, certPem); }
  catch (e) {
    if (idDps) {
      const c = await chamar("GET", `${base}/dps/${idDps}`, null, keyPem, certPem).catch(() => null);
      if (c?.status === 200 && c.json?.chaveAcesso) return { ok: true, chaveAcesso: c.json.chaveAcesso, recuperada: true };
    }
    throw e;
  }
  if (r.status >= 200 && r.status < 300 && r.json?.chaveAcesso) {
    return { ok: true, chaveAcesso: r.json.chaveAcesso, idDps: r.json.idDps, alertas: r.json.alertas ?? null,
      nfseXml: r.json.nfseXmlGZipB64 ? gunzipB64(r.json.nfseXmlGZipB64) : null };
  }
  const erros = r.json?.erros ?? r.json?.Erros ?? [];
  return { ok: false, status: r.status, erros: erros.length ? erros : [{ Codigo: String(r.status), Descricao: r.json?.bruto?.slice(0, 500) || "Resposta inesperada do sistema nacional" }] };
}

// Evento (ex.: cancelamento): assina o pedRegEvento e envia para /nfse/{chave}/eventos.
async function evento({ pfxB64, senha, xml, ambiente, chave }) {
  const base = BASES[ambiente];
  if (!base) throw new Error("Ambiente inválido");
  if (!/^\d{50}$/.test(chave || "")) throw new Error("Chave de acesso inválida");
  const { keyPem, certPem } = abrirPfx(pfxB64, senha);
  const assinado = assinar(xml, keyPem, certPem, "infPedReg");
  const pedidoRegistroEventoXmlGZipB64 = zlib.gzipSync(Buffer.from(assinado, "utf8")).toString("base64");
  const r = await chamar("POST", `${base}/nfse/${chave}/eventos`, { pedidoRegistroEventoXmlGZipB64 }, keyPem, certPem);
  if (r.status >= 200 && r.status < 300 && !r.json?.erro && !r.json?.erros?.length) {
    return { ok: true, eventoXml: r.json?.eventoXmlGZipB64 ? gunzipB64(r.json.eventoXmlGZipB64) : null };
  }
  const e = r.json?.erro ? [r.json.erro] : (r.json?.erros ?? r.json?.Erros ?? []);
  return { ok: false, status: r.status, erros: e.length ? e : [{ Codigo: String(r.status), Descricao: r.json?.bruto?.slice(0, 500) || "Resposta inesperada do sistema nacional" }] };
}

export { abrirPfx, assinar };
if (process.env.NO_SERVER) {} else http.createServer(async (req, res) => {
  const responder = (s, o) => { res.writeHead(s, { "Content-Type": "application/json" }); res.end(JSON.stringify(o)); };
  if (req.method === "GET" && req.url === "/saude") return responder(200, { ok: true });
  if (req.headers.authorization !== `Bearer ${TOKEN}`) return responder(401, { ok: false, erros: [{ Descricao: "Não autorizado" }] });
  const acoes = { "/emitir": emitir, "/evento": evento };
  const acao = req.method === "POST" ? acoes[req.url] : null;
  if (!acao) return responder(404, { ok: false });
  let corpo = "";
  req.on("data", (c) => { corpo += c; if (corpo.length > 5e6) req.destroy(); });
  req.on("end", async () => {
    try { responder(200, await acao(JSON.parse(corpo))); }
    catch (e) {
      const msg = /PKCS#12 MAC|Invalid password/i.test(String(e?.message)) ? "Senha do certificado incorreta" : e?.message || "Erro";
      responder(200, { ok: false, erros: [{ Codigo: "TRANSMISSOR", Descricao: msg }] });
    }
  });
}).listen(PORT, () => console.log(`Transmissor ouvindo na porta ${PORT}`));
