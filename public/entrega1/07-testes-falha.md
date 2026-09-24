# Evidência 7 — Testes de falha

## Caso 1 — Retorno sem cookie temporário

### Preparação
Iniciei o fluxo de login em uma janela comum e parei na página do provedor. Copiei a URL de autorização e abri essa URL em uma janela privativa, que não possuía o cookie `__Host-oauth-tx`.

### Pedido enviado
Concluí o login na janela privativa, fazendo com que o provedor redirecionasse para a rota de callback sem o cookie temporário original.

### Resultado esperado
A rota de retorno deve recusar a autenticação, pois o cookie `__Host-oauth-tx` não está presente. Nenhuma sessão deve ser criada.

### Resultado observado
A autenticação foi recusada e a aplicação informou que o cookie de transação estava ausente (`missing_transaction_cookie`). Nenhuma sessão foi criada.

---

## Caso 2 — State alterado

### Preparação
Iniciei um novo login e parei na página do provedor antes de fornecer as credenciais.

### Pedido enviado
Alterei um único caractere do parâmetro `state` na URL de autorização e prossegui com o processo de autenticação.

### Resultado esperado
A rota de retorno deve recusar a solicitação porque o valor de `state` recebido não corresponde ao valor armazenado na transação. A troca do código de autorização não deve ocorrer.

### Resultado observado
A autenticação foi recusada porque o `state` recebido não corresponde ao `state` armazenado para a transação. A troca do código de autorização não foi realizada.

---

## Caso 3 — Reutilização da transação

### Preparação
Realizei um login com sucesso e localizei a requisição de retorno no painel Network do navegador.

### Pedido enviado
Copiei a URL da requisição de retorno e abri essa mesma URL novamente após a conclusão do login.

### Resultado esperado
A segunda tentativa deve falhar, pois a transação OAuth já foi consumida e removida do banco de dados.

### Resultado observado
A segunda tentativa foi recusada porque a transação OAuth já havia sido consumida e removida do banco. A aplicação retornou erro de transação não encontrada (`transaction_not_found`) e não criou uma nova sessão.

---

## Caso 4 — Sessão expirada

### Preparação
Criei uma sessão de teste realizando o login normalmente. Em seguida, acessei o console do D1.

### Pedido enviado
Executei o comando:

    UPDATE sessions
    SET expires_at = 0;

Depois recarreguei a aplicação e consultei `/api/me`.

### Resultado esperado
O endpoint `/api/me` deve responder com HTTP 401, pois a sessão está expirada.

### Resultado observado
O endpoint `/api/me` respondeu com HTTP 401. A sessão não foi considerada válida porque o campo `expires_at` estava expirado.

---

## Caso 5 — Origem inválida na saída

### Preparação
Mantive uma sessão válida aberta na URL da aplicação e abri outra origem, `https://example.com`.

### Pedido enviado
No console do navegador da origem diferente, executei:

    fetch("URL_BASE/oauth/logout", {
      method: "POST",
      credentials: "include"
    });

### Resultado esperado
A rota de logout deve recusar a operação porque a requisição possui uma origem inválida. A sessão original deve permanecer válida na aplicação.

### Resultado observado
A requisição de logout originada de `https://example.com` foi recusada pela aplicação. A sessão original permaneceu válida quando retornei à aplicação.

---

## Caso 6 — Reutilização do cookie revogado

### Preparação
Em uma sessão exclusiva do laboratório, copiei temporariamente o valor do cookie `__Host-session` pelas ferramentas de desenvolvimento.

### Pedido enviado
Executei o logout, tentei restaurar temporariamente o mesmo valor do cookie e consultei `/api/me`.

### Resultado esperado
O endpoint `/api/me` deve responder com HTTP 401, pois a sessão correspondente ao cookie revogado foi removida do banco de dados.

### Resultado observado
O endpoint `/api/me` respondeu com HTTP 401. A sessão correspondente ao cookie reutilizado não existia mais no D1 após o logout.

A cópia temporária do cookie foi apagada imediatamente após o teste.

---

## Conclusão

Os seis testes demonstraram que a aplicação recusa situações de retorno sem transação, alteração do estado OAuth, reutilização de transações, sessões expiradas, solicitações de logout provenientes de origem inválida e reutilização de cookies de sessão revogados.
