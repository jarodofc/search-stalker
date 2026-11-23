# zFORENSE v3.0 (Sherlock com Alma Florence)

Plataforma modular de Pericia Digital, OSINT e Threat Intelligence para GitHub + Vercel, combinando **Liquid Glass**, **Material UX**, iconografia vetorial duotone (SVG) e a paleta **Noite em Baker Street / Pergaminho de Florenca**.

## Destaques da Atualizacao v3.0
- **Liquid Glass + Material UX:** superficies translúcidas com `backdrop-filter: blur() saturate(165%)`, destaque especular superior, anel de borda de 1px, cantos `22px`, botoes em pilula (3 niveis) e curvas de movimento Material 3 (`cubic-bezier(0.2, 0, 0, 1)`).
- **Acessibilidade Cross-Browser:** suporte a `@media (prefers-reduced-transparency: reduce)` combinado com o botao **Solido** (`data-solid-panels="true"`) para Safari e leitura prolongada.
- **Tipografia Customizada:** `Cormorant Garamond` (titulos >= 18px), `Plus Jakarta Sans` (interface e corpo) e `Courier Prime` (carimbos investigativos, hashes e hex dump), com CSP liberado em `vercel.json`.
- **Command Lens (`⌘K` / `Ctrl+K`):** busca instantanea de modulos no topo + Floating Glass Rail (desktop) e Floating Pill Dock (mobile).
- **Design Tokens:** arquivo `tokens.json` pronto para Figma Variables e Style Dictionary.

## Deploy no GitHub + Vercel
1. Extraia os arquivos na raiz do repositorio (`index.html`, `vercel.json`, `package.json`, `tokens.json`, `api/`, `assets/`).
2. Envie via Git (`git add . && git commit -m "feat: zFORENSE v3.0 Sherlock com Alma Florence" && git push`).
3. Na Vercel, adicione `VT_API_KEY` em **Environment Variables** e mantenha **Framework Preset: Other** sem comando de build.
