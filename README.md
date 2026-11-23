# SHERLOCK 221B • Prism Intelligence Deck (v4.1)

Plataforma modular de Pericia Digital, Proxy & VPN Lab, OSINT e Threat Intelligence pronta para GitHub + Vercel.

## Como publicar sem conflito de versoes antigas
1. Extraia o conteudo deste ZIP diretamente na raiz do seu repositorio Git (`index.html`, `package.json`, `vercel.json`, `api/` e `assets/` devem ficar diretamente na raiz).
2. Apague arquivos obsoletos de versoes antigas (como `assets/js/local-engines.js`, caso ainda exista).
3. Envie tudo via Git:
   ```powershell
   git add -A
   git commit -m "fix: SHERLOCK 221B Prism v4.1 completo"
   git push
   ```
4. Na Vercel, mantenha **Framework Preset: Other** (Build Command e Output Directory vazios). Opcionalmente adicione `VT_API_KEY` em **Environment Variables** (sem a chave, o modulo Threat Intel usa automaticamente o fallback publico AlienVault OTX).
