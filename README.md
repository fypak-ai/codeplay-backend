# CodePlay Backend API

Backend REST para o [CodePlay Game Website](https://fypak-ai.github.io/game-website/).  
Node.js + Express + SQLite (`better-sqlite3`) — pronto para deploy no **Railway**.

## 🚀 Deploy rápido (Railway)

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template)

1. Fork / clone este repo
2. Crie um novo projeto no Railway e conecte o repo
3. Adicione a variável de ambiente:
   - `JWT_SECRET` = qualquer string secreta longa

Railway sobe automaticamente com `npm start`.

## 📡 Endpoints

### Auth
| Método | Rota | Descrição |
|--------|------|-----------|
| POST | `/api/auth/register` | Criar conta |
| POST | `/api/auth/login` | Login |
| GET | `/api/auth/me` | Perfil (requer token) |

### Usuários
| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/users` | Leaderboard (top 50) |
| GET | `/api/users/:id` | Perfil público |
| PATCH | `/api/users/me` | Atualizar avatar |

### Apps
| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/apps` | Todos os apps |
| GET | `/api/apps/mine` | Meus apps (auth) |
| POST | `/api/apps` | Criar app (auth) |
| DELETE | `/api/apps/:id` | Deletar app (auth) |
| POST | `/api/apps/:id/purchase` | Comprar app (auth) |

### Ferramentas Hacker
| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/hack-tools/mine` | Minhas ferramentas (auth) |
| POST | `/api/hack-tools` | Criar ferramenta (auth) |
| DELETE | `/api/hack-tools/:id` | Deletar ferramenta (auth) |

## 🔑 Autenticação

Envie o token JWT no header:
```
Authorization: Bearer <token>
```

## 🛠️ Local

```bash
npm install
node server.js
# → http://localhost:3000
```
