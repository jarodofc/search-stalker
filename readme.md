# GlassOSINT — Intelligence Panel

[![Design System](https://img.shields.io/badge/Design-Liquid%20Glass%20%2F%20Material%20UX-blueviolet?style=for-the-badge&logo=apple)](#)
[![Tech Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20CSS3%20%7C%20Vanilla%20JS-important?style=for-the-badge&logo=javascript)](#)
[![OSINT](https://img.shields.io/badge/Category-OSINT%20%2F%20Data%20Aggregation-success?style=for-the-badge&logo=shield)](#)

> **GlassOSINT** é um painel de inteligência e consulta de dados robusto, construído para ser uma interface de usuário premium. Ele combina a estética translúcida do **Liquid Glass** da Apple com os princípios de interação do **Material UX**, entregando uma experiência fluida, responsiva e altamente resiliente.

---

## 📑 Sumário
1. [Visão Geral](#1-visão-geral)
2. [Design System](#2-design-system)
3. [Arquitetura de Dados (Fallback)](#3-arquitetura-de-dados-fallback)
4. [Módulos Implementados](#4-módulos-implementados)
5. [Referências Técnicas e Citações](#5-referências-técnicas-e-citações)
6. [Como Executar](#6-como-executar)

---

## 1. Visão Geral
O projeto foi idealizado para centralizar consultas rápidas de dados públicos (CNPJ, CPF, Placas) e investigações OSINT (Sherlock) em uma única interface. O grande diferencial é a **resiliência**: se uma API falhar, o sistema chaveia automaticamente para uma fonte secundária, garantindo que o usuário nunca fique sem resposta.

## 2. Design System

### 2.1 Liquid Glass (Apple iOS)
A interface adota o conceito do novo material dinâmico da Apple. Em vez de apenas um desfoque (blur) simples, o CSS foi projetado para simular a refração da luz:
*   **Fundo Contextual:** O body possui gradientes radiais que interagem com o vidro.
*   **Borda Especular:** Um pseudo-elemento `::before` aplica um gradiente linear nas bordas via `mask-composite`, criando o efeito de luz batendo na espessura do vidro.
*   **Saturação:** Uso de `backdrop-filter: blur(24px) saturate(180%)` para manter as cores vibrantes por trás da interface.

### 2.2 Material UX
A usabilidade foi refinada com padrões do Material Design:
*   **Ripple Effect:** O botão primário possui uma animação de onda de toque (`@keyframes ripple`) que se expande a partir do clique do usuário.
*   **Elevação e Feedback:** Cartões e botões reagem ao `hover` (levantando levemente) e ao `active` (encolhendo), simulando toque físico.
*   **Floating Labels:** Inputs utilizam o padrão de *floating label*, onde o texto descritivo se move para cima quando o campo é focado, limpando a interface visual.

### 2.3 Ícones Vetorizados
Para garantir escalabilidade e nitidez em telas Retina, todos os ícones são do **Google Material Symbols (Rounded)**. Os ícones nos resultados são mapeados dinamicamente via JavaScript com base nas chaves do JSON (ex: `email` mapeia para `mail`, `uf` para `map`).

## 3. Arquitetura de Dados (Fallback)

Para evitar pontos únicos de falha, as requisições de API utilizam uma arquitetura em cascata (`tryFallback`).

*   **Módulo CNPJ:** Tenta `MinhaReceita` → `BrasilAPI` → `ReceitaWS`.
*   **Módulo CPF:** Tenta `CP
