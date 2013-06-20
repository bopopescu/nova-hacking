from __future__ import print_function
import base64 as b64
import kerberos as krb
import struct
import sys


def debug(p, v):
    print("{0}: {1}".format(p.upper(), v), file=sys.stderr)


class GSSAPIClient(object):
    def __init__(self, principal, dbg=debug):
        self.authname = principal
        self.debug = dbg

    def part1(self):
        init_rc, self.krbctx = krb.authGSSClientInit(self.authname)
        step1_rc = krb.authGSSClientStep(self.krbctx, '')
        return b64.b64decode(krb.authGSSClientResponse(self.krbctx))

    def part2(self, server_resp):
        step2_rc = krb.authGSSClientStep(self.krbctx,
                                         b64.b64encode(server_resp))

        if krb.authGSSClientResponse(self.krbctx) is None:
            return ''
        else:
            return b64.b64decode(krb.authGSSClientResponse(self.krbctx))

    SEC_LAYER_MASKS = {
        None: 1,
        'integrity': 2,
        'confidentiality': 4
    }

    def part3(self, tok, user, sec_layers='any'):
        unwrapped_tok = self.unwrap(tok)
        sec_layers_supported_raw = ord(unwrapped_tok[0])
        max_server_msg_size_raw = '\x00' + unwrapped_tok[1:4]
        max_server_msg_size = struct.unpack("!L", max_server_msg_size_raw)[0]

        sec_layers_supported = []
        for name, mask in self.SEC_LAYER_MASKS.items():
            if sec_layers_supported_raw & mask > 0:
                sec_layers_supported.append(name)

        self.debug('gss api security layers supported', sec_layers_supported)
        self.debug('gss max serverout size', max_server_msg_size)

        sec_layer_choice = 0
        if sec_layers == 'any':
            for mask in self.SEC_LAYER_MASKS.values():
                if mask & sec_layers_supported_raw > sec_layer_choice:
                    sec_layer_choice = mask
        else:
            for mask_name in sec_layers:
                mask = self.SEC_LAYER_MASKS[mask_name]
                if mask & sec_layers_supported_raw > sec_layer_choice:
                    sec_layer_choice = mask

        if sec_layer_choice == 0:
            raise "No supported security layer!"

        self.security_layer = sec_layer_choice
        sec_layer_choice = 4

        resp = chr(sec_layer_choice) + unwrapped_tok[1:4]
        return self.wrap(resp, user)

    def wrap(self, message, user):
        # don't pass user to function because otherwise our
        # message (including auth choice) will be overriden
        # for kerberos-1.1.1
        krb.authGSSClientWrap(self.krbctx, b64.b64encode(message + user))
        return b64.b64decode(krb.authGSSClientResponse(self.krbctx))

    def unwrap(self, raw_message):
        message_enc = b64.b64encode(raw_message)
        krb.authGSSClientUnwrap(self.krbctx, message_enc)
        return b64.b64decode(krb.authGSSClientResponse(self.krbctx))

    def encrypt(self, message):
        if self.security_layer == self.SEC_LAYER_MASKS[None]:
            return message
        elif self.security_layer == self.SEC_LAYER_MASKS['integrity']:
            krb.authGSSClientWrap(self.krbctx,
                                  b64.b64encode(message),
                                  None, False)
            return b64.b64decode(krb.authGSSClientResponse(self.krbctx))
        elif self.security_layer == self.SEC_LAYER_MASKS['confidentiality']:
            krb.authGSSClientWrap(self.krbctx,
                                  b64.b64encode(message),
                                  None, True)
            return b64.b64decode(krb.authGSSClientResponse(self.krbctx))
        else:
            raise Exception(
                "Unknown security layer type '{0}'".format(self.security_layer)
            )

    def decrypt(self, raw_message):
        if self.security_layer == self.SEC_LAYER_MASKS[None]:
            return raw_message
        elif self.security_layer == self.SEC_LAYER_MASKS['integrity']:
            message = b64.b64encode(raw_message)
            krb.authGSSClientUnwrap(self.krbctx, message)
            return b64.b64decode(krb.authGSSClientResponse(self.krbctx))
        elif self.security_layer == self.SEC_LAYER_MASKS['confidentiality']:
            message = b64.b64encode(raw_message)
            krb.authGSSClientUnwrap(self.krbctx, message)
            return b64.b64decode(krb.authGSSClientResponse(self.krbctx))
        else:
            raise Exception(
                "Unknown security layer type '{0}'".format(self.security_layer)
            )
