---
title: Instalar o driver NVIDIA 580 em placas mais antigas (GTX 10, GTX 900, GTX 750, Titan V)
summary: Placas das famílias Maxwell, Pascal e Volta precisam do driver legado NVIDIA 580. O módulo do kernel é compilado na sua máquina e, com o Secure Boot ligado, você cadastra uma chave uma única vez, numa tela do firmware na próxima inicialização.
proposal_text:
  snapshot-before: Tirar um snapshot do sistema, para poder voltar se o novo driver der problema.
  enable-rpmfusion: Ativar os repositórios RPM Fusion free e nonfree, de onde vêm os pacotes do driver.
  install-driver: Instalar o driver NVIDIA 580, a ferramenta que compila o módulo do kernel e o nvidia-smi.
  enroll-key: Preparar o cadastro da chave de assinatura de módulos desta máquina, protegido por uma senha de uso único que você escolhe.
  reboot: Reiniciar e confirmar a chave na tela azul de cadastro, com a mesma senha.
---
## Este guia é para a sua placa?

Rode no terminal:

```sh
lspci -nnk -d 10de:
```

Cada dispositivo NVIDIA mostra o seu id entre colchetes: `[10de:1b81]` é
uma GeForce GTX 1070. Este guia é para as famílias Maxwell, Pascal e
Volta: GeForce GTX 750 e série GTX 900, série GTX 10 (da 1050 à 1080 Ti),
Titan X e Titan Xp, Titan V e as Quadro e Tesla das mesmas gerações. A
lista da NVIDIA das placas suportadas pelo driver 580 é a referência.

GeForce GTX 16, RTX 20 e todas as mais novas usam o driver NVIDIA atual,
não este. Placas Kepler (GTX 600 e GTX 700, exceto a GTX 750) não têm
mais nenhum driver NVIDIA mantido; nelas, fique com o driver livre
nouveau.

## Por que este driver é diferente

Os drivers NVIDIA a partir da série 590 não suportam mais essas placas. A
série 580 é a última que suporta, e recebe só correções de segurança e de
compatibilidade, sem novidades. A NVIDIA classifica a 580 como um ramo de
suporte longo, com fim em junho de 2028, e anunciou atualizações de
segurança para as GeForce Maxwell, Pascal e Volta até outubro de 2028.

Os módulos abertos do kernel da NVIDIA exigem uma placa Turing ou mais
nova, então essas placas usam o módulo fechado da NVIDIA. Ele é compilado
na sua máquina para cada kernel (pelo akmods) e, com o Secure Boot
ligado, o firmware só o carrega depois que você cadastra a chave de
assinatura desta máquina (uma machine owner key, MOK).

## Antes de começar

- Uns 15 minutos, conexão de rede e um teclado na máquina para a
  reinicialização (a tela de cadastro precisa dele).
- Veja se o Secure Boot está ligado: `mokutil --sb-state`.
- Tire um snapshot antes (o primeiro passo abaixo), para poder voltar.

## Passos

1. Tire um snapshot do sistema.

2. Ative os repositórios RPM Fusion (free e nonfree):

   ```sh
   sudo dnf install https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
   ```

3. Instale o driver, o compilador do módulo e o `nvidia-smi`:

   ```sh
   sudo dnf install akmod-nvidia-580xx xorg-x11-drv-nvidia-580xx xorg-x11-drv-nvidia-580xx-cuda
   ```

   `dnf search nvidia-580xx` lista os pacotes deste ramo.

4. Com o Secure Boot ligado, cadastre a chave de assinatura. O akmods
   assina os módulos que compila com uma chave desta máquina; se
   `/etc/pki/akmods/certs/public_key.der` ainda não existir,
   `sudo kmodgenca -a` cria. Depois:

   ```sh
   sudo mokutil --import /etc/pki/akmods/certs/public_key.der
   ```

   Escolha uma senha de uso único e lembre dela até reiniciar.

5. Espere o módulo compilar (alguns minutos) e confira:

   ```sh
   modinfo -F version nvidia
   ```

   Quando o módulo está pronto, aparece uma versão 580. Se não aparecer
   nada, rode `sudo akmods --force` e leia o log indicado.

6. Reinicie. Uma tela azul (MOK management) aparece uma vez: escolha
   Enroll MOK, Continue, Yes, digite a senha e depois Reboot. Se perder a
   tela, repita o passo 4 e reinicie.

## Confira se funcionou

```sh
nvidia-smi
lsmod | grep -E '^(nvidia|nouveau)'
mokutil --list-enrolled | grep -i akmods
```

O `nvidia-smi` mostra a sua placa e o driver 580, o `nvidia` está
carregado e o `nouveau` não.

## Atualizações do kernel

Cada kernel novo precisa do módulo compilado de novo; o akmods faz isso na
inicialização seguinte, que demora um pouco mais. O ramo 580 recebe
correções de compatibilidade com o kernel só de vez em quando, então um
kernel muito novo pode chegar antes de o módulo compilar para ele. Se
isso acontecer, escolha o kernel anterior no menu de inicialização e
espere uma atualização do driver.

O Sway precisa da opção `--unsupported-gpu` para iniciar com este driver.

## Como voltar

Volte para o snapshot que você tirou, ou remova o driver e reinicie (o
nouveau volta):

```sh
sudo dnf remove '*nvidia-580xx*'
```
