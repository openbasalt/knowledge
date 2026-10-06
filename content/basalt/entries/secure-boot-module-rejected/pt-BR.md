---
title: Um módulo do kernel não carrega com "Key was rejected by service"
summary: Com o Secure Boot ligado, o kernel só carrega módulos assinados por uma chave em que o firmware confia. Um módulo compilado na sua máquina (akmods ou DKMS) é assinado com uma chave local, que você cadastra uma única vez.
proposal_text:
  enroll-key: Preparar o cadastro da chave de assinatura do akmods desta máquina, protegido por uma senha de uso único que você escolhe.
  reboot: Reiniciar e confirmar a chave na tela azul de cadastro, com a mesma senha.
---
## O que significa

O `modprobe` mostra `Key was rejected by service` (erro `EKEYREJECTED`)
quando o Secure Boot está ligado e o módulo não está assinado por uma
chave em que o sistema confia. Os módulos que vêm com o kernel são
assinados pela distribuição; módulos de terceiros compilados na sua
máquina (pelo akmods ou DKMS, por exemplo um driver de vídeo ou de rede)
são assinados com uma chave desta máquina, que o firmware só aceita
depois que você a cadastra como machine owner key (MOK).

Desligar o Secure Boot não é a solução: isso tira uma proteção contra
código de inicialização adulterado para todos os módulos, não só para
este.

## Verifique

```sh
mokutil --sb-state
modinfo -F signer MODULO
mokutil --list-enrolled | grep -i -A2 subject
```

Troque MODULO pelo nome do módulo. Se quem assinou for a chave do akmods
desta máquina e ela não estiver na lista de cadastradas, cadastre-a.

## Correção

1. Crie a chave se ela ainda não existir (`/etc/pki/akmods/certs/public_key.der`):
   `sudo kmodgenca -a` e depois recompile o módulo: `sudo akmods --force`.
2. Peça ao firmware para cadastrá-la:

   ```sh
   sudo mokutil --import /etc/pki/akmods/certs/public_key.der
   ```

   Escolha uma senha de uso único.
3. Reinicie. Na tela azul MOK management escolha Enroll MOK, Continue,
   Yes, digite a senha e depois Reboot.

Depois de reiniciar, `modprobe MODULO` carrega o módulo. O DKMS usa uma
chave própria (`/var/lib/dkms/mok.pub`); cadastre esse arquivo quando o
módulo vier do DKMS.
