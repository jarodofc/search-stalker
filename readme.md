# GlassOSINT — Painel de Consultas com Fallback e Liquid Glass

## 1. Visão Geral
Este projeto implementa um painel web para consultas de **CNPJ, CPF, Placa de Veículo e OSINT (Sherlock)**, utilizando o conceito de **Liquid Glass** da Apple adaptado para a web, e um sistema de **fallback automático** entre múltiplas APIs para garantir resiliência.

## 2. Arquitetura de Fallback

### 2.1 CNPJ
A consulta de CNPJ tenta, em ordem, as seguintes fontes:
1.  **MinhaReceita** (`minhareceita.org`) — API open-source, sem limites agressivos.
2.  **BrasilAPI** (`brasilapi.com.br`) — Projeto comunitário brasileiro, amplamente utilizado [citation:7].
3.  **ReceitaWS** (`receitaws.com.br`) — API leve e rápida, ideal para consultas ágeis [citation:7].

A função `tryFallback()` executa cada fonte sequencialmente. Se uma lançar exceção ou retornar erro, a próxima é tentada automaticamente.

### 2.2 CPF
A consulta de CPF utiliza a **CPFHub** como fonte primária, com a chave fornecida. Em caso de falha (API indisponível, chave inválida, etc.), o sistema retorna um objeto com **validação local básica** (verificação de formato), garantindo que o usuário não fique sem resposta.

**Nota:** A validação local não substitui uma consulta real, mas serve como *graceful degradation*.

### 2.3 Placa
A consulta de placa utiliza a **Parallelum FIPE** (`fipe.parallelum.com.br`), uma API pública e gratuita que fornece dados de veículos e valores FIPE [citation:15]. Como não há uma segunda API pública gratuita amplamente disponível para consulta de placa sem chave, o fallback retorna um erro controlado com mensagem amigável.

### 2.4 Sherlock (OSINT)
O módulo Sherlock realiza busca de *username* nas seguintes plataformas:
- **GitHub** (API pública)
- **Reddit** (API pública via proxy CORS)

A implementação utiliza um proxy CORS (`allorigins.win`) para contornar restrições de *same-origin* do navegador.

## 3. Design: Liquid Glass

### 3.1 Adaptação Web
O material **Liquid Glass** da Apple é descrito como um material dinâmico que combina propriedades ópticas do vidro com fluidez, criando uma camada funcional distinta para controles e navegação [citation:6][citation:12].

Na web, implementamos uma aproximação usando:
- `backdrop-filter: blur(20px) saturate(180%)` — para o desfoque e saturação do vidro.
- `border: 1px solid rgba(255,255,255,0.15)` — para a borda sutil.
- Um pseudo-elemento `::before` com gradiente e `mask-composite` para simular a **borda especular** (o brilho na borda do vidro).
- `box-shadow` interno para dar profundidade e o efeito de "luz passando pelo vidro".

### 3.2 Princípios Aplicados
Segundo as diretrizes da Apple:
- **Hierarquia:** O vidro é usado apenas em elementos de *interface* (header, cards, formulários), não no conteúdo em si, mantendo a distinção entre camada funcional e conteúdo [citation:12].
- **Legibilidade:** O fundo escuro com gradientes garante contraste suficiente para o texto branco sobre o vidro.
- **Contenção:** O efeito é aplicado com moderação (header e containers principais), evitando sobrecarga visual [citation:6].

## 4. Ícones
Todos os ícones são da biblioteca **Material Symbols Rounded**, garantindo consistência visual e vetorização. O ícone do site (favicon) é uma impressão digital branca, alinhada ao tema de OSINT/investigação.

## 5. Limitações Conhecidas
- **CORS:** As APIs de CPF e algumas de OSINT podem bloquear requisições diretas do navegador. O proxy CORS é usado onde necessário, mas pode adicionar latência.
- **Placa:** A ausência de uma segunda API pública gratuita limita o fallback para este módulo.
- **Sherlock:** A versão web é uma adaptação simplificada; a ferramenta original (CLI) realiza buscas em muito mais plataformas.

## 6. Referências Técnicas
- **Liquid Glass (Apple):** Documentação oficial descreve o material como uma camada funcional que combina vidro e fluidez, usado para controles e navegação [citation:6].
- **APIs de CNPJ:** O padrão de fallback entre múltiplos provedores (BrasilAPI, ReceitaWS, MinhaReceita, etc.) é uma prática comum para aumentar a resiliência [citation:7][citation:13].
- **FIPE (Parallelum):** API gratuita que fornece dados de veículos e valores FIPE, amplamente utilizada pela comunidade [citation:15].
