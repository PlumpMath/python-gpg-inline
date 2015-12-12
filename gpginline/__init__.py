import gnupg


class Document(object):

    def __init__(self, string, _start, _end):
        self._string = string
        self._start = _start
        self._end = _end
        self.parts = []

    @staticmethod
    def from_string(string, gpg=None, _start=0, _end=None):
        if gpg is None:
            gpg = gnupg.GPG()
        if _end is None:
            _end = len(string)
        doc = Multipart(string, _start, _end)
        doc._parse_parts(_start, _end, gpg)
        if len(doc.parts) == 1:
            return doc.parts[0]
        else:
            return doc

    def _parse_parts(self, start, end, gpg):

        for typ in Encrypted, Signed:
            part, part_start, part_end = self._parse(start, end, typ, gpg)
            if part is not None:
                self._parse_parts(0, part_start, gpg)
                self.parts.append(part)
                self._parse_parts(part_end, end, gpg)
                return

        self.parts.append(Plain(self._string, start, end))

    def _parse(self, start, end, typ, gpg):
        start, end = typ.find(self._string, start, end)
        if start == -1:
            return None, -1, -1
        part = self._decrypt(typ, start, end, gpg)
        if part is None:
            return None, -1, -1
        return part, start, end

    @staticmethod
    def _decrypt(self, typ, start, end, gpg):
        ciphertext = self._string[start:end]
        try:
            # Note that the decrypt() method will still do what we want if
            # we're dealing with a message that is only signed; it will verify
            # the result. Also, the verify() method doesn't return the
            # extracted data, which makes it unsuitable.
            plaintext = gpg.decrypt(ciphertext)
            ret = typ(self._string, start, end)
            ret.plaintext = plaintext
        except ValueError:
            # NOTE: python-gnupg doesn't seem to actually check for malformed
            # input, so the underlying error is something about an unexpected
            # status code.
            #
            # We take this error to mean that the text we passed wasn't really
            # a ciphertext and report that to the caller.
            return None

    def _str_slice(self):
        return self._string[self._start:self._end]

    def __str__(self):
        return str(self._str_slice())

    def __unicode__(self):
        return unicode(self._str_slice())


class Multipart(Document):
    pass


class Plain(Document):
    pass


class Encrypted(Multipart):
    start_token = '-----BEGIN PGP MESSAGE-----'
    end_token = '-----END PGP MESSAGE-----'

    @staticmethod
    def find(string, start_idx=0, end_idx=None):
        """Find the the first possible encrypted message in string.

        The search will start at the index `start_idx` and end at `end_idx`.
        If these parameters are not supplied, the entire string will be
        searched.

        Note that false positives are possible; the caller should attempt to
        decrypt the message in order to determine if it is really an encrypted
        message.

        The return value is a tuple (n, m) such that the message is
        string[n:m], or (-1, -1) if no encrypted message is found.

        The value (-1, -1) is chosen so that the caller may safely write:

            start, end = Encrypted.find(text)
        """
        if end_idx is None:
            end_idx = len(string)
        start = string.find(Encrypted.start_token, start_idx, end_idx)
        if start == -1:
            return -1, -1
        end = string.find(Encrypted.end_token, start, end_idx)
        if end == -1:
            return -1, -1
        end += len(Encrypted.end_token)
        return start, end


class Signed(Multipart):
    start_token = '-----BEGIN PGP SIGNED MESSAGE-----'
    mid_token = '-----BEGIN PGP SIGNATURE-----'
    end_token = '-----END PGP SIGNATURE-----'

    @staticmethod
    def find(string, start, end):
        """Find the first possible signed message in string.

        This behaves the same way as `Encrypted.find`, except that it searches
        for signed messages.
        """
        start = string.find(Signed.start_token)
        if start == -1:
            return -1, -1
        mid = string.find(Signed.mid_token, start)
        if mid == -1:
            return -1, -1
        end = string.find(Signed.end_token, mid)
        if end == -1:
            return -1, -1
        end += len(Signed.end_token)
        return start, end
