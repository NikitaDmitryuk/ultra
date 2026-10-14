import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

source = Path(__file__).resolve().with_name('ansible-template-fixture.py')
spec = importlib.util.spec_from_file_location('subscription', source)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class SubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.p = {'domain':'sync.example.com','upstream_domain':'sync.example.com','bot_port':8444}

    def test_render_verifies_tls_and_keeps_bot_and_xhttp_separate(self):
        text = m.nginx(self.p).decode()
        self.assertIn('proxy_pass https://127.0.0.1:8444;', text)
        self.assertIn('proxy_ssl_verify on;', text)
        self.assertIn('proxy_ssl_name sync.example.com;', text)
        self.assertIn('access_log off;', text)
        self.assertNotIn('grpc_pass', text)
        self.assertNotIn('edge.example.com', text)

    # Ownership transactions, drift guards and published endpoint regression
    # cases now run against native modules in test-ansible-owned-file.py and
    # test-ansible-ingress.py, rather than the deleted SSH installer.


class RealNginxTests(unittest.TestCase):
    @unittest.skipUnless(__import__('os').environ.get('ULTRA_TEST_NGINX_IMAGE'), 'set ULTRA_TEST_NGINX_IMAGE for isolated Docker integration')
    def test_sni_vhosts_and_verified_bot_tls(self):
        import http.server, os, socket, ssl, subprocess, threading, time, uuid
        image=os.environ['ULTRA_TEST_NGINX_IMAGE']
        self.assertTrue(image.startswith('nginx:'))
        def port():
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o755)
            cert=root/'cert.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=sync.example.com','-addext','subjectAltName=DNS:sync.example.com,DNS:edge.example.com'],check=True,capture_output=True)
            class Bot(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200);self.end_headers();self.wfile.write(b'bot-fixture')
                def log_message(self,*args):pass
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Bot)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(cert,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            front=port();http=port()
            p={'domain':'sync.example.com','upstream_domain':'sync.example.com','bot_port':server.server_port}
            rendered=m.nginx(p).decode()+m.nginx({'domain':'edge.example.com','path':'/connect','backend_port':port()},443).decode()
            for name in ('sync.example.com','edge.example.com'):
                rendered=rendered.replace('/etc/letsencrypt/live/'+name+'/fullchain.pem','/fixtures/cert.pem').replace('/etc/letsencrypt/live/'+name+'/privkey.pem','/fixtures/key.pem')
            rendered=rendered.replace('/etc/ssl/certs/ca-certificates.crt','/fixtures/cert.pem').replace('listen 443 ssl http2;',f'listen 127.0.0.1:{front} ssl http2;').replace('listen 80;',f'listen 127.0.0.1:{http};').replace('/var/www/ultra-site','/fixtures/site').replace('/var/log/nginx/ultra-subscription-error.log','stderr').replace('/var/log/nginx/ultra-vpn-error.log','stderr')
            (root/'site').mkdir();(root/'site/index.html').write_text('edge-fixture')
            header='worker_processes 1; pid /tmp/nginx.pid; error_log stderr crit; events {} http { client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; '
            (root/'nginx.conf').write_text(header+rendered+'}')
            name='ultra-subscription-test-'+uuid.uuid4().hex
            try:
                subprocess.run(['docker','run','--detach','--rm','--name',name,'--network','host','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--mount','type=bind,src='+tmp+',dst=/fixtures,readonly','--entrypoint','nginx',image,'-c','/fixtures/nginx.conf','-g','daemon off;'],check=True,capture_output=True)
                ctx=ssl.create_default_context(cafile=str(cert));ctx.minimum_version=ssl.TLSVersion.TLSv1_2
                def request(host,path='/'):
                    with socket.create_connection(('127.0.0.1',front),timeout=2) as raw:
                        with ctx.wrap_socket(raw,server_hostname=host) as sock:
                            sock.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
                            response=__import__('http.client',fromlist=['HTTPResponse']).HTTPResponse(sock);response.begin();return response.status,response.read()
                for attempt in range(50):
                    try:
                        status,body=request('sync.example.com','/healthz')
                        if status==200:break
                    except OSError:pass
                    time.sleep(.1)
                self.assertEqual((status,body),(200,b'bot-fixture'))
                self.assertEqual(request('edge.example.com'),(200,b'edge-fixture'))
                self.assertEqual(request('edge.example.com','/healthz')[0],404)
                # A wrong upstream certificate name must fail, never silently disable TLS verification.
                config=root/'nginx.conf'
                config.write_text(config.read_text().replace('proxy_ssl_name sync.example.com;', 'proxy_ssl_name wrong.example.com;'))
                subprocess.run(['docker','exec',name,'nginx','-c','/fixtures/nginx.conf','-s','reload'],check=True,capture_output=True)
                for _ in range(50):
                    status,_=request('sync.example.com','/healthz')
                    if status==502:break
                    time.sleep(.1)
                self.assertEqual(status,502)

            finally:
                subprocess.run(['docker','rm','-f',name],capture_output=True)
                server.shutdown();server.server_close();thread.join(timeout=3)

if __name__=='__main__':unittest.main()
