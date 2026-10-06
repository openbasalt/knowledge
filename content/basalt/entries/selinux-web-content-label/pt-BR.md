---
title: Servidor web responde 403 ou "Permission denied" para arquivos de um diretório novo
summary: O nginx e o httpd só podem ler arquivos rotulados como conteúdo web. Arquivos num diretório novo (por exemplo /srv/www) ou movidos de um diretório pessoal mantêm um rótulo que o servidor não lê; uma regra de contexto de arquivo e uma rerrotulagem resolvem.
proposal_text:
  label-web-root: Adicionar uma regra permanente do SELinux que rotula /srv/www como conteúdo web e rerrotular os arquivos de lá.
---
## O que significa

Num sistema com SELinux o servidor web roda no domínio `httpd_t` (o nginx
também) e pode ler arquivos rotulados `httpd_sys_content_t`. Um diretório
criado fora de `/var/www`, ou arquivos movidos (não copiados) do seu
diretório pessoal, ficam com outro rótulo (`default_t`, `var_t` ou
`user_home_t`), então o servidor recebe "Permission denied" mesmo com as
permissões de arquivo certas, e os visitantes veem 403 Forbidden.

## Verifique

```sh
ls -Z /srv/www
sudo ausearch -m avc -ts recent -c nginx
matchpathcon /srv/www
```

Uma negação com `scontext=system_u:system_r:httpd_t:s0` e `tcontext=unconfined_u:object_r:default_t:s0` (ou
`user_home_t`) nos seus arquivos confirma.

## Correção

Rotule o diretório como conteúdo web de forma permanente e depois
rerrotule o que já está lá:

```sh
sudo semanage fcontext -a -t httpd_sys_content_t '/srv/www(/.*)?'
sudo restorecon -Rv /srv/www
```

Use o seu diretório no lugar de `/srv/www`. Não use `chcon` (uma
rerrotulagem desfaz) nem coloque o SELinux em modo permissivo: os dois
escondem o problema em vez de resolver. Se o servidor também precisar
escrever ali (uploads), o tipo é `httpd_sys_rw_content_t`, só no
diretório que precisa.
