#! /usr/bin/env python3
import sys
import time
import html
import os
import asyncio

TESTCASE_DIR = "test_case/"

def printPage(hostname, port):
    print('Content-type: text/html', end='\r\n\r\n')
    scope = ""
    _id = ""

    for i in range(0, len(hostname)):
        scope += f"""
              <th scope="col">{hostname[i]}:{port[i]}</th>
        """

        _id += f"""
              <td><pre id="session{i}" class="mb-0"></pre></td>
        """

    print(
    '''
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>NP Project 3 Sample Console</title>
        <link
          rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css"
          integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2"
          crossorigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css?family=Source+Code+Pro"
          rel="stylesheet"
        />
        <link
          rel="icon"
          type="image/png"
          href="https://cdn0.iconfinder.com/data/icons/small-n-flat/24/678068-terminal-512.png"
        />
        <style>
          * {
            font-family: 'Source Code Pro', monospace;
            font-size: 1rem !important;
          }
          body {
            background-color: #212529;
          }
          pre {
            color: #cccccc;
          }
          b {
            color: #01b468;
          }
        </style>
      </head>
      <body>
        <table class="table table-dark table-bordered">
          <thead>
            <tr>
    '''
    )
    print(scope)
    print(
    '''
            </tr>
          </thead>
          <tbody>
            <tr>
    '''
    )
    print(_id)
    print(
    '''
            </tr>
          </tbody>
        </table>
      </body>
    </html>
    '''
    )

def output_shell(session, content):
    content = html.escape(content)
    content = content.replace('\n', '&NewLine;')
    print(f"<script>document.getElementById('{session}').innerHTML += '{content}';</script>")
    sys.stdout.flush()

def output_command(session, content):
    content = html.escape(content)
    content = content.replace('\n', '&NewLine;')
    print(f"<script>document.getElementById('{session}').innerHTML += '<b>{content}</b>';</script>")
    sys.stdout.flush()

class connHandler:
    def __init__(self, hostname, port, fname, session_name):
        self.hostname = hostname
        self.port = port
        self.fd = open(TESTCASE_DIR + fname)
        self.session_name = session_name

    async def connect(self):
        reader, writer = await asyncio.open_connection(self.hostname, self.port)
        while True:
            data = await reader.read(1024)
            data = data.decode()
            if len(data) == 0:
                break
            #print(data, end='')
            output_shell(self.session_name, data)
            if '% ' in data:
                msg = self.fd.readline()
                #print(msg, end='')
                output_command(self.session_name, msg)
                writer.write(msg.encode())
                #time.sleep(0.5)
                # await asyncio.sleep(0.5)

def parse_q(q):
    trimmed = [i.split('=')[1] for a, i in enumerate(q.split("&")) if len(i)!=3]
    hostname = trimmed[::3]
    port = trimmed[1::3]
    fname = trimmed[2::3]
    return hostname, port, fname

async def merge_tasks(hostname, port, fname):
    conn = []
    for i in range(0, len(hostname)):
        session_name = 'session' + str(i)
        conn.append(connHandler(hostname[i], int(port[i]), fname[i], session_name).connect())
    ret = await asyncio.gather(*conn, return_exceptions=True)
    return ret

if __name__ == "__main__":
    q = os.getenv("QUERY_STRING")
    hostname, port, fname = parse_q(q)

    printPage(hostname, port)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(merge_tasks(hostname, port, fname))
    loop.close()

