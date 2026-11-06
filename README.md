# Transmissor Nota Fácil (NFS-e Nacional)

Pequeno serviço que assina a DPS e a envia ao sistema nacional usando o certificado A1 da empresa.

## Publicar no Render (plano gratuito)
1. Crie uma conta em https://render.com e um repositório no GitHub só com esta pasta `transmissor`.
2. No Render: New → Web Service → escolha o repositório.
   - Runtime: Node · Build command: `npm install` · Start command: `npm start` · Plano: Free
3. Em Environment, adicione `TRANSMISSOR_TOKEN` com uma senha longa e aleatória (40+ caracteres).
4. Depois de publicado, abra `https://SEU-SERVICO.onrender.com/saude` — deve mostrar `{"ok":true}`.
5. No Nota Fácil, informe o endereço do serviço e o mesmo token.

Observação: no plano gratuito o serviço "dorme" após 15 min sem uso; a primeira emissão depois disso pode levar ~1 minuto.
