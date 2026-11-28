# OTP via Telegram — homologação

Substitui o PIN estático por código de seis dígitos solicitado explicitamente, expiração de cinco minutos, limite de cinco tentativas e consumo atômico no banco. Sessão de oito horas e cookie novo; sessões antigas não são aceitas. A interface preserva o estilo existente.

**Não publicar sem validar:** aplicar `otp-migration.sql` uma única vez ao banco existente, configurar `Z_OTP_BOT_TOKEN` com token novo rotacionado (nunca reutilizar o exposto), `Z_OTP_CHAT_ID` com o chat privado do proprietário, e `Z_OTP_ENABLED=true` somente no ambiente de teste autorizado. Manter as variáveis Z_GATE existentes. Executar `node --test tests/otp.test.mjs` e validar emissão, expiração, consumo concorrente, bloqueios, entrega e recuperação de acesso antes de promover. Não alterar o ambiente atual até concluir a validação. Não utilizar o OTP como único fator de operações administrativas críticas. Não guardar códigos em logs.

O limite global por painel é de um envio por minuto e três por quinze minutos. O envio depende do Telegram; não há fallback inseguro. O token antigo deve ser revogado pelo proprietário no BotFather.
