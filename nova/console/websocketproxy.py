# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

'''
Websocket proxy that is compatible with OpenStack Nova.
Leverages websockify.py by Joel Martin
'''

import Cookie
from select import select
import socket

import websockify

import nova.console.sasl_helper as sasl_helper

from oslo.config import cfg

from nova.consoleauth import rpcapi as consoleauth_rpcapi
from nova import context
from nova.openstack.common import log as logging


wsp_krb_opts = [
    cfg.BoolOpt('vnc_krb_auth',
                default=False,
                help='Whether to use Kerberos authentication '
                     'between the vnc proxy and nova hosts'
                     ' (you must have your qemu vnc set up to use'
                     ' SASL authentication to use this)'),
    cfg.StrOpt('vnc_krb_username',
               default='admin',
               help='The kerberos username for the proxy to use when '
                    'communicating with nova hosts (only used when '
                    'vnc_krb_auth is set to true')
]

CONF = cfg.CONF

CONF.register_opts(wsp_krb_opts)

LOG = logging.getLogger(__name__)


class NovaWebSocketProxy(websockify.WebSocketProxy):
    def __init__(self, *args, **kwargs):
        super(NovaWebSocketProxy, self).__init__(unix_target=None,
                                                 target_cfg=None,
                                                 ssl_target=None,
                                                 *args, **kwargs)

    def new_client(self):
        """
        Called after a new WebSocket connection has been established.
        """
        cookie = Cookie.SimpleCookie()
        cookie.load(self.headers.getheader('cookie'))
        token = cookie['token'].value
        ctxt = context.get_admin_context()
        rpcapi = consoleauth_rpcapi.ConsoleAuthAPI()
        connect_info = rpcapi.check_token(ctxt, token=token)

        if not connect_info:
            LOG.audit("Invalid Token: %s", token)
            raise Exception(_("Invalid Token"))

        host = connect_info['host']
        port = int(connect_info['port'])

        # Connect to the target
        self.msg("connecting to: %s:%s" % (host, port))
        LOG.audit("connecting to: %s:%s" % (host, port))
        tsock = self.socket(host, port, connect=True)

        # Handshake as necessary
        if connect_info.get('internal_access_path'):
            tsock.send("CONNECT %s HTTP/1.1\r\n\r\n" %
                        connect_info['internal_access_path'])
            while True:
                data = tsock.recv(4096, socket.MSG_PEEK)
                if data.find("\r\n\r\n") != -1:
                    if not data.split("\r\n")[0].find("200"):
                        LOG.audit("Invalid Connection Info %s", token)
                        raise Exception(_("Invalid Connection Info"))
                    tsock.recv(len(data))
                    break

        if self.verbose and not self.daemon:
            print(self.traffic_legend)

        # Start proxying
        try:
            if CONF.vnc_krb_auth:
                self.msg('Using SASL/GSSAPI Authentication '
                         'between proxy and host')

                auth_id = CONF.vnc_krb_username
                sasl_gss = sasl_helper.RFBSASLClient(sock=tsock,
                                                     msg=self.msg,
                                                     authid=auth_id)
                sasl_gss.connect()

                sasl_fake = sasl_helper.RFBSASLServer(sasl_gss,
                                                      sendf=self.send_frames,
                                                      recvf=self.recv_frames,
                                                      msg=self.msg)
                sasl_fake.connect()

                self.do_proxy(tsock, sasl_gss.recv_unwrap, sasl_gss.wrap)
            else:
                self.do_proxy(tsock)
        except Exception:
            if tsock:
                tsock.shutdown(socket.SHUT_RDWR)
                tsock.close()
                self.vmsg("%s:%s: Target closed" % (host, port))
                LOG.audit("%s:%s: Target closed" % (host, port))
            raise

    def do_proxy(self, target, target_recv_cb=lambda r, d: r(d),
                               target_send_cb=lambda x: x):
        self.msg('Beginning mitm proxy mode...')
        """
        Proxy client WebSocket to normal target socket.
        """
        cqueue = []
        c_pend = 0
        tqueue = []
        rlist = [self.client, target]

        while True:
            wlist = []

            if tqueue:
                wlist.append(target)
            if cqueue or c_pend:
                wlist.append(self.client)
            ins, outs, excepts = select(rlist, wlist, [], 1)
            if excepts:
                raise Exception("Socket exception")

            if self.client in outs:
                # Send queued target data to the client
                c_pend = self.send_frames(cqueue)

                cqueue = []

            if self.client in ins:
                # Receive client data, decode it, and queue for target
                bufs, closed = self.recv_frames()
                tqueue.extend(bufs)

                if closed:
                    # TODO(websockify): What about blocking on client socket?
                    self.vmsg("%s:%s: Client closed connection" % (
                        self.target_host, self.target_port))
                    raise self.CClose(closed['code'], closed['reason'])

            if target in outs:
                # Send queued client data to the target
                dat_raw = tqueue.pop(0)
                dat = target_send_cb(dat_raw)
                sent = target.send(dat)
                if sent == len(dat):
                    self.traffic(">")
                else:
                    # requeue the remaining data
                    tqueue.insert(0, dat[sent:])
                    self.traffic(".>")

            if target in ins:
                # Receive target data, encode it and queue for client
                buf = target_recv_cb(target.recv, self.buffer_size)
                if len(buf) == 0:
                    self.vmsg("%s:%s: Target closed connection" % (
                        self.target_host, self.target_port))
                    raise self.CClose(1000, "Target closed")

                cqueue.append(buf)
                self.traffic("{")
