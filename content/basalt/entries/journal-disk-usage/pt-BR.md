---
title: O sistema de arquivos raiz enche com logs e pacotes baixados
summary: O journal do sistema e o cache de pacotes podem crescer até vários gigabytes. Reduzir o journal a um tamanho fixo e limpar os pacotes baixados devolve o espaço sem mexer nos seus arquivos.
proposal_text:
  vacuum-journal: Reduzir o journal do sistema a 500 MB, removendo os arquivos mais antigos.
  clean-packages: Remover os arquivos de pacotes baixados que já estão instalados.
---
## Verifique

```sh
df -h /
journalctl --disk-usage
sudo du -sh /var/cache/libdnf5 /var/cache/dnf 2>/dev/null
```

No btrfs, o `df` também conta os snapshots: snapshots antigos guardam o
espaço de arquivos apagados ou substituídos depois que foram tirados. No
Basalt OS, `basalt disk` mostra quanto cada snapshot ocupa sozinho.

## Correção

Reduza o journal (as entradas mais antigas saem primeiro) e limpe o cache
de pacotes:

```sh
sudo journalctl --vacuum-size=500M
sudo dnf clean packages
```

Para manter o journal pequeno de vez, defina um limite num arquivo
drop-in e reinicie o journald:

```ini
# /etc/systemd/journald.conf.d/size.conf
[Journal]
SystemMaxUse=500M
```

```sh
sudo systemctl restart systemd-journald
```

Remover as entradas mais antigas do journal não tem volta, e os
snapshots não as trazem de volta (`/var/log` não faz parte de um snapshot
do sistema).
