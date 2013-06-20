from __future__ import print_function
import eventlet
import nova.console.krb as krb
import struct
import sys


def get_debug(pr=lambda x: print(x, file=sys.stderr), prefix=None):
    act_prefix = ""
    if prefix is not None:
        act_prefix = '(' + prefix + ') '

    def debug(p, v):
        pr("{0}{1}: {2}".format(act_prefix, p.upper(), v))

    return debug


class RFBSASLServer(object):
    def __init__(self, pobj, sendf, recvf, msg=None):
        self.send_frames = sendf
        self.recv_frames = recvf
        self.prop_obj = pobj
        if msg is None:
            self.debug = get_debug(prefix='mitm server')
        else:
            self.debug = get_debug(msg, prefix="mitm server")

        self.frames = []

    def get_frame(self):
        if len(self.frames) == 0:
            self.frames.extend(self.recv_frames()[0])

        return self.frames.pop()

    def connect(self):
        self.send_frames([self.prop_obj.rfb_version])
        client_version = self.get_frame()
        self.debug('rfb client version', client_version)
        if client_version != self.prop_obj.rfb_version:
            debug_str = ('version mismatch: {0} vs {1} '
                         '(but blindly forging ahead)')
            self.debug('rfb',
                       debug_str.format(client_version[:-1],
                       self.prop_obj.rfb_version[:-1]))

        self.send_frames(['\x01\x01'])  # send only a sec type of plain

        client_sec_type = self.get_frame()

        if client_sec_type != '\x01':
            debug_str = "RFB Security type {0} is not supported"
            raise Exception(debug_str.format(repr(client_sec_type)))

        self.send_frames(['\x00' * 4])

        self.debug('rfb', 'handshake complete, passing to main proxy')

        if len(self.frames) > 0:
            raise 'Cheese!' + repr(self.frames)


class RFBSASLClient(object):
    def __init__(self,
                 host='localhost', port=5900, sock=None,
                 flip_continue=True, authid="admin",
                 msg=None):

        if sock is None:
            self.sock = eventlet.connect((host, port))
        else:
            self.sock = sock

        self.flip_continue = flip_continue
        self.authid = authid

        if msg is None:
            self.debug = get_debug(prefix='mitm client')
        else:
            self.debug = get_debug(msg, prefix='mitm client')

    def negotiate_version(self, major_ver, minor_ver):
        self.debug('rfb version', str(major_ver) + '.' + str(minor_ver))
        return (3, 8)

    def connect(self, version_cb=None):

        # Negotiate version
        if (version_cb is None):
            version_cb = self.negotiate_version

        version_str = self.sock.recv(12)
        self.debug('rfb version (raw)', version_str[:-1])

        version_parts = version_str[4:11].split('.')
        majv_out, minv_out = version_cb(int(version_parts[0]),
                                        int(version_parts[1]))

        new_version_str = "RFB {majv:03}.{minv:03}\n".format(majv=majv_out,
                                                             minv=minv_out)

        self.rfb_version = new_version_str

        self.sock.sendall(new_version_str)

        # Negotiate SASL Security
        num_sec_types = ord(self.sock.recv(1))

        if num_sec_types < 1:
            self.debug('rfb', 'no security types')
            __, err_msg = self.receive_with_len()
            self.debug('rfb', err_msg)
            raise Exception('RFB did not send any security types: ' + err_msg)

        sec_types_raw = self.sock.recv(num_sec_types)
        sec_types_nums = [ord(x) for x in sec_types_raw]
        self.debug('rfb sec types', repr(sec_types_nums))

        if 20 not in sec_types_nums:
            self.debug('rfb issue', 'SASL (20) not available')
            raise Exception('SASL was not an available RFB security type')

        self.sock.sendall(chr(20))

        # Negotiate GSSAPI Security
        sasl_mechs_len, sasl_mechs_str = self.receive_with_len(null_term=False)
        if sasl_mechs_len < 1:
            self.debug('sasl issue', 'no mechanisms available')
            raise Exception('No SASL mechanisms available')

        sasl_mechs = sasl_mechs_str.split(',')

        if 'GSSAPI' not in sasl_mechs:
            self.debug('sasl issue', 'GSSAPI not an available mechanism')
            raise Exception('GSSAPI is not an available SASL mechanism')

        self.debug('sasl mechs', sasl_mechs)

        self.send_clientstep('GSSAPI', null_term=False)

        # Do GSSAPI Exchanges

        # GSS part 1
        gssclient = krb.GSSAPIClient("vnc@sross.localdomain", dbg=self.debug)
        gss_part1 = gssclient.part1()

        self.send_clientstep(gss_part1)

        # GSS part 2
        server_challenge = self.receive_serverstep()

        output_tok = gssclient.part2(server_challenge)
        self.send_clientstep(output_tok)

        # GSS part 3
        input_tok = self.receive_serverstep()
        sec_layer_tok = gssclient.part3(input_tok, self.authid)
        self.send_clientstep(sec_layer_tok)

        # End security negotiation

        # basically just says "don't continue"
        final_message = self.receive_serverstep()

        __, auth_result_message = self.receive_with_len()

        # None here means that we got a "length" of 0, which is actually
        # the result code indicating authentication OK
        # Otherwise, the "result code" (as of 3.8) is just a message length
        # for an error message
        if auth_result_message is None:
            self.debug('sasl', 'authentication successful')
        else:
            self.debug('sasl auth error', auth_result_message)
            debug_str = 'Error in SASL Authentication: "{0}"'
            raise Exception(debug_str.format(auth_result_message))

        self.gssclient = gssclient

    def gsswrap(self, msg):
        return self.gssclient.encrypt(msg)

    def gssunwrap(self, msg):
        return self.gssclient.decrypt(msg)

    def wrap(self, msg):
        msg_enc = self.gsswrap(msg)
        msg_enc_len = struct.pack("!L", len(msg_enc))
        return msg_enc_len + msg_enc

    def recv_unwrap(self, recvf, default_buffer_size):
        msg_enc_len_raw = recvf(4)
        if len(msg_enc_len_raw) < 4:
            return ''

        msg_enc_len = struct.unpack("!L", msg_enc_len_raw)[0]
        msg_enc = recvf(msg_enc_len)
        msg = self.gssunwrap(msg_enc)
        return msg

    def send_clientstep(self, base_out, null_term=True):
        sasl_clientout = base_out
        if null_term:
            sasl_clientout += '\x00'

        sasl_clientout_len = struct.pack(">L", len(sasl_clientout))
        self.sock.sendall(sasl_clientout_len + sasl_clientout)

    def receive_with_len(self, null_term=True):
        recv_len = struct.unpack(">L", self.sock.recv(4))[0]
        if recv_len > 0:
            recv_val = self.sock.recv(recv_len)

            if null_term:
                # [:-1] gets rid of the null character at the end of the string
                return (recv_len, recv_val[:-1])
            else:
                return (recv_len, recv_val)
        else:
            return (0, None)

    # note: in qemu, the continue bit seems to be switched
    def receive_serverstep(self):
        sasl_serverout_len, sasl_serverout = self.receive_with_len()

        sasl_continue_raw = self.sock.recv(1)
        sasl_continue = sasl_continue_raw != '\x00'

        if (self.flip_continue):
            sasl_continue = not sasl_continue

        self.debug('sasl continue', sasl_continue)

        if sasl_serverout_len > 0:
            self.debug('sasl serverout len', sasl_serverout_len)

            return sasl_serverout
        else:
            return None
