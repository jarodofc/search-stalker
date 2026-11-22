# GlassOSINT • iOS Liquid Edition (Assinado por KIIK HACKING)

[![Design](https://img.shields.io/badge/UI-iOS%20Liquid%20Glass%20%7C%20Dynamic%20Island-0A84FF?style=for-the-badge&logo=apple)](#)
[![Security](https://img.shields.io/badge/Security-P2P%20E2EE%20%7C%20KIIK%20HACKING-30D158?style=for-the-badge&logo=shield)](#)
[![Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Web%20Crypto%20API-5E5CE6?style=for-the-badge&logo=javascript)](#)

> Painel de investigação digital (OSINT), web scraping e central veicular com interface inspirada no **iOS Liquid Glass** (Dynamic Island, ícones Squircle, listas agrupadas translúcidas e animações spring), protegido por criptografia P2P silenciosa e assinado por **KIIK HACKING**.

---

## 📑 Sumário
1. [Interface iOS Liquid Glass](#1-interface-ios-liquid-glass)
2. [Criptografia P2P & Assinatura (KIIK HACKING)](#2-criptografia-p2p--assinatura-kiik-hacking)
3. [Aplicativos Disponíveis](#3-aplicativos-disponíveis)
4. [Segurança e Blindagem](#4-segurança-e-blindagem)
5. [Como Publicar](#5-como-publicar)

---

## 1. Interface iOS Liquid Glass

- **Home Screen com Ícones Squircle:** Grade responsiva estilo iPhone com ícones arredondados (`border-radius` proporcional), brilho especular interno e feedback tátil (`scale` spring).
- **Dynamic Island:** Barra superior flutuante com status em tempo real e indicador de sessão criptografada.
- **Inset Grouped Lists:** Resultados e formulários organizados em blocos translúcidos (`backdrop-filter: blur(36px) saturate(210%)`) com tipografia nativa Apple (`-apple-system` / `SF Pro`).
- **100% Responsivo (Mobile & Desktop):** Otimizado para Safari no iOS (`viewport-fit=cover`, `apple-mobile-web-app-capable`) e navegadores desktop sem bloqueios falsos por zoom ou barra lateral.

---

## 2. Criptografia P2P & Assinatura (KIIK HACKING)

A criptografia P2P opera de forma transparente em segundo plano via **Web Crypto API** (sem botões ou telas extras na interface):

- **Sessão E2EE (ECDH P-256 + AES-256-GCM):** Deriva chaves efêmeras para selar o armazenamento local (`localStorage`) da sessão.
- **Assinatura Criptográfica (`KIIK HACKING`):** Todo relatório copiado ou exportado em `.json` recebe automaticamente o envelope assinado com `signed_by: "KIIK HACKING"`, timestamp ISO e assinatura **HMAC-SHA256**.

---

## 3. Aplicativos Disponíveis

1. **Veículos MG:** Organização de Placa, RENAVAM, CPF/CNPJ e Chassi/CRV com cópia em 1 toque, consulta automática do titular (CPF/CNPJ) e acesso direto a **DETRAN-MG (Situação e ATPV-e), SENATRAN (SERPRO) e Multas PBH**.
2. **OSINT Web:** Varredura progressiva em **Redes Sociais, Sites Adultos, Sites de Namoro e Sites de Aposta** com status em tempo real e Google Dorks.
3. **Scraper:** Extração de metadados (`title`, `description`, `generator`), e-mails públicos, telefones BR, redes sociais, títulos (`H1/H2`) e links externos.
4. **CPF:** Consulta via `CPFHub.io` com fallback local para validação matemática e Região Fiscal.
5. **CNPJ:** Consulta cadastral e Quadro Societário (`BrasilAPI` → `MinhaReceita` → `CNPJ.ws`).
6. **Vazamentos:** Checagem de exposição de e-mail via `XposedOrNot API`.
7. **CEP:** Endereço completo e coordenadas (`BrasilAPI v2` → `ViaCEP`).
8. **IP / Geo:** Geolocalização, operadora (ISP) e ASN (`ipwho.is` → `ipapi.co`).
9. **Domínio:** Registros DNS (`A`, `MX`, `NS`, `TXT` via Google DoH) e dados RDAP (`Registro.br` / `RDAP.org`).
10. **DDD Brasil:** Estado e lista de municípios atendidos (`BrasilAPI`).

---

## 4. Segurança e Blindagem

- **Bloqueio de Atalhos de Inspeção:** Intercepta `F12`, `Ctrl+Shift+I/J/C/K`, `Cmd+Option+I/J/C`, `Ctrl+U`, `Ctrl+S` e clique direito (`contextmenu`) sem disparar falsos positivos no iPhone ou em telas com barra lateral.
- **Isolamento em IIFE:** Todo o código roda fechado em `(() => { 'use strict'; ... })()`, sem expor funções ou chaves no escopo global `window`.
- **Sanitização XSS:** Todos os dados dinâmicos passam por `escapeHtml()` antes de entrar no DOM.

---

## 5. Como Publicar

1. Substitua o arquivo `index.html` no seu repositório GitHub / Vercel.
2. Aguarde o deploy concluir e abra o link no Safari ou navegador desktop.
