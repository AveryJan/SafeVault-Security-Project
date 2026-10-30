import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode
from safevault import SafeVault


class SafeVaultSecurityTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.app = SafeVault(Path(self.dir.name) / 'test.db')

    def tearDown(self):
        self.dir.cleanup()

    def req(self, method, path, payload=None, token=None, query=''):
        body = json.dumps(payload).encode() if payload is not None else b''
        env = {'REQUEST_METHOD':method,'PATH_INFO':path,'QUERY_STRING':query,'CONTENT_LENGTH':str(len(body)), 'CONTENT_TYPE':'application/json','wsgi.input':io.BytesIO(body)}
        if token:
            env['HTTP_AUTHORIZATION'] = 'Bearer ' + token
        result = {}
        def start_response(status, headers):
            result['status'] = int(status.split()[0])
            result['headers'] = dict(headers)
        raw = b''.join(self.app(env,start_response)).decode()
        return result['status'], json.loads(raw) if result['headers']['Content-Type'].startswith('application/json') else raw, result['headers']

    def register_login(self, username='alice', password='StrongPassword123!'):
        assert self.req('POST','/register',{'username':username,'password':password})[0] == 201
        return self.req('POST','/login',{'username':username,'password':password})[1]['token']

    def test_registration_validation_rejects_role_escalation(self):
        self.assertEqual(400, self.req('POST','/register',{'username':'alice','password':'StrongPassword123!', 'role':'admin'})[0])
        self.assertEqual(400, self.req('POST','/register',{'username':'a','password':'weak'})[0])

    def test_sql_injection_login_is_rejected(self):
        self.register_login()
        status, _, _ = self.req('POST','/login',{'username':"' OR 1=1 --",'password':'anything'})
        self.assertEqual(401,status)

    def test_auth_required_and_wrong_password(self):
        self.register_login()
        self.assertEqual(401, self.req('GET','/secrets')[0])
        self.assertEqual(401, self.req('POST','/login',{'username':'alice','password':'wrong'})[0])

    def test_user_cannot_access_admin(self):
        token = self.register_login()
        self.assertEqual(403,self.req('GET','/admin/users',token=token)[0])

    def test_admin_can_access_admin_after_local_provisioning(self):
        self.app.create_user('siteadmin','AnotherStrongPassword123!',role='admin',privileged=True)
        token = self.req('POST','/login',{'username':'siteadmin','password':'AnotherStrongPassword123!'})[1]['token']
        self.assertEqual(200,self.req('GET','/admin/users',token=token)[0])

    def test_owner_isolation_and_parameterized_inserts(self):
        alice = self.register_login()
        bob = self.register_login('bob')
        text = "private'); DROP TABLE users; --"
        self.assertEqual(201,self.req('POST','/secrets',{'title':'note','content':text},alice)[0])
        self.assertEqual([],self.req('GET','/secrets',token=bob)[1]['secrets'])
        self.assertEqual(text,self.req('GET','/secrets',token=alice)[1]['secrets'][0]['content'])
        self.assertEqual(200,self.req('GET','/me',token=bob)[0])

    def test_xss_html_escaped_and_csp(self):
        status, page, headers = self.req('GET','/preview',query=urlencode({'text':'<script>alert(1)</script>'}))
        self.assertEqual(200,status)
        self.assertNotIn('<script>',page)
        self.assertIn('&lt;script&gt;',page)
        self.assertIn("default-src 'none'",headers['Content-Security-Policy'])

    def test_logout_revokes_token(self):
        token = self.register_login()
        self.assertEqual(200,self.req('POST','/logout',{},token)[0])
        self.assertEqual(401,self.req('GET','/me',token=token)[0])

    def test_invalid_json_and_body_limit(self):
        self.assertEqual(400,self.req('POST','/register',[])[0])
        token = self.register_login()
        self.assertEqual(400,self.req('POST','/secrets',{'title':'x','content':1},token)[0])
        env = {'REQUEST_METHOD':'POST','PATH_INFO':'/login','CONTENT_LENGTH':'99999','CONTENT_TYPE':'application/json','wsgi.input':io.BytesIO(b'')}
        result={}
        self.app(env,lambda s,h: result.update(status=int(s.split()[0])))
        self.assertEqual(413,result['status'])


if __name__ == '__main__':
    unittest.main()
