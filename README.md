# CofreKey

Gerenciador de senhas com autenticador de dois fatores (2FA), feito com HTML, CSS e JavaScript puro.
O usuário decora só uma **senha mestra**. As outras senhas e os códigos de verificação ficam
guardados no próprio aparelho, criptografados. Não existe servidor: nada sai do navegador.

Projeto da disciplina de Interação Humano-Computador, FATEC Sorocaba, 2026.
Grupo: Felipe Kenji Sawada Nagai, Miguel Oliveira Goes e Murillo Martins Biazio.

**Demonstração:** `https://murillo-mb12.github.io/CofreKey_Prototipo/`

## Funcionalidades

- **Cofre de senhas:** cadastro, busca, favoritos, mostrar e copiar senha, editar e excluir com "Desfazer".
- **Avisos antes de salvar:** o app avisa quando a senha é fraca ou já é usada em outra conta.
- **Códigos de verificação (2FA):** códigos de 6 dígitos que mudam a cada 30 segundos, no mesmo padrão
  do Google Authenticator (TOTP, RFC 6238). Funcionam sem internet.
- **Leitura de QR code** pela câmera ou por um print, e importação da exportação do Google Authenticator.
- **Código ligado à senha:** a senha de um site mostra o código de verificação do mesmo site.
- **Gerador de senhas** com tamanho e tipos de caracteres escolhidos.
- **Código de recuperação** para abrir o cofre se a senha mestra for esquecida.
- **Bloqueio automático** por falta de uso (com aviso 15 s antes) e ao sair do app.
- **Backup criptografado** (exportar e restaurar) e **importação de senhas** do Chrome, Edge, Firefox e Bitwarden (CSV).
- **Instalável (PWA)** e funciona sem internet. Tema claro e escuro. Atalhos de teclado.

## Como a segurança funciona

```
senha mestra ──PBKDF2-SHA256 (600.000 iterações)──► chave A ─┐
                                                              ├─ abrem a CHAVE DE DADOS (AES-256, aleatória)
código de recuperação ──PBKDF2-SHA256───────────────► chave B ─┘
                                                                     │
                                         AES-256-GCM ◄───────────────┘
                                              │
                         senhas e códigos criptografados no localStorage
```

- A senha mestra e o código de recuperação **nunca são salvos**.
- Trocar a senha mestra só recriptografa a chave de dados.
- O AES-GCM detecta qualquer alteração no arquivo: o app diferencia "senha errada" de "arquivo danificado".
- Depois de 5 senhas erradas, o desbloqueio fica suspenso por um tempo crescente. Esse bloqueio fica salvo:
  recarregar a página não zera a contagem.
- Se o cofre for alterado em outra aba, esta aba bloqueia em vez de sobrescrever os dados.
- Toda a criptografia usa a Web Crypto API do navegador. A página tem Content Security Policy e não carrega
  nada de outros sites (fontes e bibliotecas ficam na pasta do projeto).

## Como executar

Não precisa instalar nada.

- **Mais simples:** abra o arquivo `index.html` no Chrome, Edge ou Firefox.
- **Com servidor local** (necessário para testar a instalação como app e o modo sem internet):
  ```bash
  npm start          # abre em http://localhost:8080
  ```
  ou `python -m http.server 8080`.

## Testes

```bash
npm test
```

São 22 testes automáticos (Node.js 20 ou mais novo, sem dependências), incluindo os vetores oficiais da
RFC 6238 para SHA-1, SHA-256 e SHA-512, a criptografia do cofre, a recuperação, o gerador e a leitura de CSV.

## Publicar no GitHub Pages

1. Crie um repositório chamado `cofrekey` no GitHub e envie todos os arquivos desta pasta.
2. No repositório, abra **Settings → Pages**.
3. Em **Branch**, escolha `main` e a pasta `/ (root)` e clique em **Save**.
4. Em um ou dois minutos o site fica disponível em `https://SEU-USUARIO.github.io/cofrekey/`.

O GitHub Pages usa HTTPS, que é obrigatório para a criptografia do navegador e para instalar o app.

## Estrutura

| Arquivo | O que faz |
|---|---|
| `index.html` | Telas e janelas do app |
| `css/app.css`, `css/fonts.css` | Visual (tema claro e escuro) e fontes locais |
| `js/app.js` | Interface: telas, listas, eventos, bloqueio, backup |
| `js/vault.js` | Cofre criptografado (PBKDF2, AES-GCM, recuperação) |
| `js/totp.js` | Códigos de verificação (TOTP/HOTP) e leitura de QR codes `otpauth://` |
| `js/passwords.js` | Gerador de senhas e medidor de força |
| `js/csv.js` | Importação de senhas por CSV |
| `js/storage.js` | Armazenamento local e aviso quando o navegador não salva |
| `js/qr.js` | Leitura (câmera e imagem) e geração de QR codes |
| `sw.js`, `manifest.webmanifest` | Funcionamento sem internet e instalação como app |
| `tests/` | Testes automáticos |
| `vendor/`, `fonts/` | Bibliotecas e fontes de terceiros, com licenças |

## Limitações conhecidas

- Os dados ficam em um navegador por vez. Para levar o cofre a outro aparelho, use o backup.
- Códigos por contador (HOTP) ainda não são aceitos; apenas TOTP.
- A derivação de chave usa PBKDF2 porque é o que a Web Crypto API oferece. O Argon2id seria mais resistente
  a ataques com placa de vídeo, mas exigiria uma biblioteca externa.
- Limpar a área de transferência depende do navegador permitir; em alguns casos isso não acontece.

## Créditos e licenças

- Código do CofreKey: licença MIT (arquivo `LICENSE`).
- [QRCode.js](https://github.com/davidshimjs/qrcodejs) (MIT) e [jsQR](https://github.com/cozmo/jsQR) (Apache-2.0), em `vendor/`.
- Fontes [Manrope](https://github.com/sharanda/manrope) e [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) (SIL Open Font License), em `fonts/`.
