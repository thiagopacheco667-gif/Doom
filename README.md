# Extrator de romfs para NSP (DOOM 2016 / Switch)

O port Android do DOOM pede a pasta `romfs` dentro da pasta do jogo
(ex.: `/storage/emulated/0/Download/DOOM Mobile/romfs`). Este script tira essa pasta
de dentro do `.nsp` do jogo.

## App Android (APK)

Instale o `Extrator-romfs-DOOM.apk` (permita instalar de fontes desconhecidas) e:

1. Toque em **Permitir acesso aos arquivos** e ative a permissão para o app.
2. **Escolher o arquivo .nsp** e **Escolher o prod.keys**.
3. Confira a pasta do jogo (padrão: `/storage/emulated/0/Download/DOOM Mobile`).
4. Toque em **Extrair romfs**. Deixe a tela ligada até terminar.

No port, escolha a pasta `DOOM Mobile`. O código do app fica em `android/`.
Para compilar: `cd android && gradle assembleRelease` (precisa do Android SDK 34).

## O que você precisa

1. O **NSP do jogo base** que você extraiu do seu cartucho ou da sua conta (NSP de update não serve).
2. O **`prod.keys` do seu próprio console**, gerado com o Lockpick_RCM. O script não traz chaves.
3. Python 3.8 ou mais novo, com `cryptography` (ou `pycryptodome`).

## No PC (Windows/Linux/macOS)

```bash
pip install cryptography
python3 nsp_romfs_extractor.py "DOOM.nsp" -k prod.keys -o "DOOM Mobile"
```

Depois copie a pasta `DOOM Mobile` (que tem a `romfs` dentro) para a pasta `Download` do telefone.

## Direto no Android (Termux)

```bash
pkg install python python-cryptography
termux-setup-storage
cd /storage/emulated/0/Download
python nsp_romfs_extractor.py DOOM.nsp -k prod.keys -o "DOOM Mobile"
```

O resultado fica em `/storage/emulated/0/Download/DOOM Mobile/romfs`. No app, escolha a
pasta `DOOM Mobile` (não a `romfs`).

## Opções

| Opção | Para que serve |
|---|---|
| `--list` | Mostra os arquivos sem extrair |
| `--exefs` | Também extrai a pasta `exefs` (main, main.npdm…) |
| `--titlekey HEX` | Titlekey manual, se o NSP não tiver o `.tik` |
| `--title-keys arquivo` | Arquivo `title.keys` (`rights_id = titlekey`) |
| `--include-control` | Também extrai o romfs do NCA Control (ícone/nome) |

## Limitações

- `.nsz` / `.xci` não são lidos: converta para `.nsp` antes (por exemplo com a ferramenta `nsz -D`).
- NSPs de update (BKTR) não são suportados. Use o jogo base.
- Tickets personalizados (não "common") precisam de `--titlekey`.
- Precisa de espaço livre igual ao tamanho do jogo (~13 GB).
