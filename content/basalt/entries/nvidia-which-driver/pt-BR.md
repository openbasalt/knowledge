---
title: Qual driver NVIDIA serve para a sua placa
summary: Placas Turing e mais novas usam o driver NVIDIA atual; placas Maxwell, Pascal e Volta precisam do driver legado 580; placas mais antigas ficam com o driver livre nouveau.
---
Descubra a sua placa e o id dela:

```sh
lspci -nn -d 10de:
```

| Geração | Exemplos | Driver |
|---|---|---|
| Turing e mais novas | GeForce GTX 16, séries RTX 20, 30, 40 e 50 | Driver NVIDIA atual com os módulos abertos do kernel |
| Maxwell, Pascal, Volta | GeForce GTX 750, série GTX 900, série GTX 10, Titan V | Driver legado NVIDIA 580 (um guia separado) |
| Kepler e mais antigas | GeForce GTX 600 e a maioria das GTX 700 | nouveau (sem driver NVIDIA mantido) |

O nouveau vem com o sistema e funciona sem configuração: ele cuida da
tela em todas as gerações, com desempenho 3D menor e sem CUDA.

Os drivers NVIDIA não são software livre e vêm de um repositório
separado. Instalar um deles substitui o nouveau, exige reiniciar e, nas
placas mais antigas, compila um módulo do kernel na sua máquina. Tire um
snapshot antes, para poder voltar.
