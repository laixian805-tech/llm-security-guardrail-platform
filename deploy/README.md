# 控制台对外入口

控制面只绑 `127.0.0.1:8010`，公网访问统一走 nginx（`nginx-asgp.conf`）。

## 端口分工

| 端口 | 用途 | 说明 |
| --- | --- | --- |
| 8010 | 控制面本体 | **只监听 127.0.0.1**，管理面不直接暴露 |
| 8000 | HTTP 入口 | nginx 反代到 8010；端侧隧道走 `127.0.0.1:8010` |
| 443 | HTTPS 入口 | 自签证书，推荐用这个 |

## 为什么是自签证书

Let's Encrypt 走不通，实测报错：

```
Detail: 43.174.224.202: Invalid response from
https://dnspod.qcloud.com/static/webblock.html?d=43-139-77-64.nip.io: 566
```

腾讯云把**未备案域名**的 80 端口请求拦到备案提示页，HTTP-01 验证取不到文件。IP 直连不受这个拦截影响，所以用自签证书 + IP 访问：

- 优点：传输加密，密码不再明文；证书 10 年有效
- 代价：浏览器首次访问会警告"证书不受信任"，需要手动继续
- SAN 同时含 `IP:43.139.77.64` 与 `DNS:43-139-77-64.nip.io`

## 重新签发

```bash
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
  -keyout /etc/nginx/ssl/asgp.key -out /etc/nginx/ssl/asgp.crt \
  -subj "/C=CN/O=ASGP/CN=43.139.77.64" \
  -addext "subjectAltName=IP:43.139.77.64,DNS:43-139-77-64.nip.io"
chmod 600 /etc/nginx/ssl/asgp.key
nginx -t && systemctl reload nginx
```

## 隧道

端侧隧道指向 8010（不再是 8000）：

```
-R 127.0.0.1:18082:127.0.0.1:8010
```

配置在 `/etc/systemd/system/asgp-test-tunnel.service.d/override.conf`。
