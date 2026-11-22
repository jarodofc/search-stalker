# GlassOSINT — Painel de Investigação Digital & P2P (KIIK HACKING)

[![Design System](https://img.shields.io/badge/Design-Liquid%20Glass%20%2F%20Material%20UX-blueviolet?style=for-the-badge&logo=apple)](#)
[![Security](https://img.shields.io/badge/Security-P2P%20E2EE%20%7C%20KIIK%20HACKING-critical?style=for-the-badge&logo=shield)](#)
[![Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Web%20Crypto%20API-important?style=for-the-badge&logo=javascript)](#)

> Painel de investigação digital (OSINT), web scraping, central veicular e criptografia ponto-a-ponto (P2P) em arquivo HTML único, assinado criptograficamente por **KIIK HACKING**.

---

## 📑 Sumário
1. [Camada de Segurança & Blindagem](#1-camada-de-segurança--blindagem)
2. [Criptografia P2P (KIIK HACKING)](#2-criptografia-p2p-kiik-hacking)
3. [Módulos Disponíveis](#3-módulos-disponíveis)
4. [Arquitetura e Boas Práticas](#4-arquitetura-e-boas-práticas)
5. [Como Usar](#5-como-usar)

---

## 1. Camada de Segurança & Blindagem

- **Bloqueio de DevTools e Atalhos:** Intercepta `F12`, `Ctrl+Shift+I/J/C/K`, `Cmd+Option+I/J/C`, `Ctrl+U`, `Ctrl+S`, clique direito (`contextmenu`) e arraste (`dragstart`).
- **Detecção Ativa de Painel de Desenvolvedor:** Monitora alterações de dimensão da janela (`outerWidth - innerWidth` / `outerHeight - innerHeight`) e aciona imediatamente uma tela de bloqueio (`#securityLock`) caso o DevTools seja aberto.
- **Isolamento Total (IIFE + Strict Mode):** Todo o código JavaScript roda encapsulado em uma função anônima isolada (`(() => { 'use strict'; ... })()`), sem expor chaves, configurações ou funções no objeto global `window`.
- **Proteção contra XSS:** Todos os dados vindos de APIs externas passam por `escapeHtml()` antes da renderização no DOM.

---

## 2. Criptografia P2P (KIIK HACKING)

Implementada nativamente via **Web Crypto API** (sem bibliotecas externas):

- **Troca de Chaves P2P:** Geração de par de chaves **ECDH (Curva P-256)** para derivação de segredo compartilhado entre dois peers.
- **Criptografia Autenticada:** **AES-256-GCM** com vetor de inicialização (`IV`) aleatório de 96 bits por mensagem.
- **Assinatura Criptográfica (`KIIK HACKING`):** Todos os pacotes P2P e relatórios exportados em `.json` recebem assinatura **HMAC-SHA256** vinculada à autoridade `KIIK HACKING` e timestamp ISO, garantindo detecção imediata de adulteração.

---

## 3. Módulos Disponíveis

1. **Criptografia P2P (KIIK):** Gera chave pública ECDH P-256, criptografa/descriptografa pacotes P2P e valida a assinatura `KIIK HACKING`.
2. **Central Veicular (MG / BH):** Organiza Placa, RENAVAM, CPF/CNPJ e Chassi/CRV com cópia em 1 clique, consulta automática do titular e atalhos para **DETRAN-MG (Situação e ATPV-e), SENATRAN (SERPRO) e Multas PBH**.
3. **Varredura OSINT (Web):** Verificação progressiva em tempo real em **Redes Sociais, Sites Adultos, Sites de Namoro e Sites de Aposta** com status visual e Google Dorks.
4. **Web Scraping (OSINT):** Extrai metadados, e-mails públicos, telefones, redes sociais, títulos (`H1/H2`) e links externos de URLs públicas.
5. **CPF:** Integração com `CPFHub.io` + fallback local (validação matemática e Região Fiscal).
6. **CNPJ:** `BrasilAPI` → `MinhaReceita` → `CNPJ.ws` (incluindo QSA).
7. **Vazamentos (E-mail):** `XposedOrNot API`.
8. **CEP / Endereço:** `BrasilAPI v2` → `ViaCEP`.
9. **IP / Geolocalização:** `ipwho.is` → `ipapi.co`.
10. **Domínio (DNS + RDAP):** `Google DNS-over-HTTPS` + `rdap.registro.br` / `rdap.org`.
11. **DDD (Brasil):** `BrasilAPI (DDD v1)`.

---

## 4. Arquitetura e Boas Práticas

- **Nota de Segurança Client-Side:** Proteções de navegador (bloqueio de `F12` e ofuscação no front-end) elevam a barreira contra inspeção casual, mas em aplicações hospedadas publicamente o ideal é mover chaves privadas para um backend ou Worker (Cloudflare Workers / Netlify Functions).
- **Delegação de Eventos:** Nenhum handler inline (`onclick`) é usado no HTML, mantendo a superfície de ataque mínima.

---

## 5. Como Usar

1. Salve o arquivo como `index.html`.
2. Abra em um navegador moderno via `https://` ou `localhost` (requerido pela **Web Crypto API** para criptografia P2P).
3. Hospede em **Cloudflare Pages**, **Netlify** ou **GitHub Pages** para uso imediato.
