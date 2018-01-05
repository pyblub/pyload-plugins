# -*- coding: utf-8 -*-

import base64
import re
import time
import os
import urllib.parse

#from module.network.RequestFactory import getURL as get_url

#from ..captcha.ReCaptcha import ReCaptcha

from pyload.core.network.hoster import Hoster
from pyload.utils.convert import to_str
from pyload.utils.layer.safethreading import Event

#TODO: test replacing self.file.plugin with self

class ShareonlineBiz(Hoster):
    __name__ = "ShareonlineBiz"
    __type__ = "hoster"
    __version__ = "0.66"
    __status__ = "testing"

    __pattern__ = r'https?://(?:www\.)?(share-online\.biz|egoshare\.com)/(download\.php\?id=|dl/)(?P<ID>\w+)'
    __config__ = [("activated", "bool", "Activated", True),
                  ("use_premium", "bool", "Use premium account if available", True),
                  ("fallback", "bool",
                   "Fallback to free download if premium fails", True),
                  ("chk_filesize", "bool", "Check file size", True),
                  ("max_wait", "int", "Reconnect if waiting time is greater than minutes", 10)]

    __description__ = """Shareonline.biz hoster plugin"""
    __license__ = "GPLv3"
    __authors__ = [("spoob", "spoob@pyload.org"),
                   ("mkaay", "mkaay@mkaay.de"),
                   ("zoidberg", "zoidberg@mujmail.cz"),
                   ("Walter Purcaro", "vuolter@gmail.com")]

    URL_REPLACEMENTS = [
        (__pattern__ + ".*",
         "http://www.share-online.biz/dl/\g<ID>")]

    CHECK_TRAFFIC = True

    RECAPTCHA_KEY = "6LdatrsSAAAAAHZrB70txiV5p-8Iv8BtVxlTtjKX"

    ERROR_PATTERN = r'<p class="b">Information:</p>\s*<div>\s*<strong>(.*?)</strong>'

    KEY_V1_PATTERN = r'(?:recaptcha(?:/api|\.net)/(?:challenge|noscript)\?k=|Recaptcha\.create\s*\(\s*["\'])((?:[\w\-]|%[0-9a-fA-F]{2})+)'
    KEY_V2_PATTERN = r'(?:data-sitekey=["\']|["\']sitekey["\']\s*:\s*["\'])((?:[\w\-]|%[0-9a-fA-F]{2})+)'

    def __init__(self, file):
        super(ShareonlineBiz, self).__init__(file)

        self.info = {}
        self.link = ''
        self._continue = Event()

    def process(self, file):
        """The 'main' method of every plugin, you **have to** overwrite it."""
        self.handle_free(file)

        self.download(self.link)

        return

    @classmethod
    def api_info(cls, url):
        print('asdf')
        # info = {}
        # field = get_url("http://api.share-online.biz/linkcheck.php",
        #                 get={'md5': "1",
        #                      'links': re.match(cls.__pattern__, url).group("ID")}).split(";")
        # try:
        #     if field[1] == "OK":
        #         info['fileid'] = field[0]
        #         info['status'] = 2
        #         info['name'] = field[2]
        #         info['size'] = field[3]  #: In bytes
        #         info['md5'] = field[4].strip().lower(
        #         ).replace("\n\n", "")  #: md5
        #
        #     elif field[1] in ("DELETED", "NOTFOUND"):
        #         info['status'] = 1
        #
        # except IndexError:
        #     pass
        #
        # return info

    def setup(self):
        self.resume_download = self.premium
        self.multiDL = False

    def handle_captcha(self):
        #self.captcha = ReCaptcha(self.pyfile)
        response, challenge = self.challenge(self.RECAPTCHA_KEY)

        m = re.search(r'var wait=(\d+);', self.data)
        self.set_wait(int(m.group(1)) if m else 30)

        res = to_str(self.load("%s/free/captcha/%d" % (self.file.url, int(time.time() * 1000)),
                        post={'dl_free': "1",
                              'recaptcha_challenge_field': challenge,
                              'recaptcha_response_field': response}))
        if res != "0":
            #self.captcha.correct()
            return res
        else:
            #self.retry_captcha()
            pass

    def handle_free(self, pyfile):
        self.wait(3)

        self.data = to_str(self.load("%s/free/" % pyfile.url,
                              post={'dl_free': "1", 'choice': "free"}))

        self.check_errors()

        res = self.handle_captcha()
        self.link = to_str(base64.b64decode(res))

        if not self.link.startswith("http://"):
            self.error(self._("Invalid url"))

        self.wait()

    def check_download(self):
        check = self.scan_download({'cookie': re.compile(r'<div id="dl_failure"'),
                                    'fail': re.compile(r'<title>Share-Online')})

        if check == "cookie":
            self.retry_captcha(5, 60, self._("Cookie failure"))

        elif check == "fail":
            self.retry_captcha(5, 5 * 60, self._("Download failed"))

        return Hoster.check_download(self)

    #: Should be working better loading (account) api internally
    def handle_premium(self, pyfile):
        self.api_data = dlinfo = {}

        html = to_str(self.load("https://api.share-online.biz/account.php",
                         get={'username': self.account.user,
                              'password': self.account.get_login('password'),
                              'act': "download",
                              'lid': self.info['fileid']}))

        self.pyload.log.debug(html)

        for line in html.splitlines():
            try:
                key, value = line.split(": ")
                dlinfo[key.lower()] = value

            except ValueError:
                pass

        if dlinfo['status'] != "online":
            self.offline()
        else:
            pyfile.name = dlinfo['name']
            pyfile.size = int(dlinfo['size'])

            self.link = dlinfo['url']

            if self.link == "server_under_maintenance":
                self.temp_offline()
            else:
                self.multiDL = True

    def check_errors(self):
        m = re.search(r'/failure/(.*?)/', self.req.last_effective_url)
        if m is None:
            self.info.pop('error', None)
            return

        errmsg = m.group(1).lower()

        try:
            self.pyload.log.error(
                errmsg,
                re.search(
                    self.ERROR_PATTERN,
                    self.data).group(1))

        except Exception:
            self.pyload.log.error(self._("Unknown error occurred"), errmsg)

        if errmsg == "invalid":
            self.fail(self._("File not available"))

        elif errmsg in ("freelimit", "size", "proxy"):
            self.fail(self._("Premium account needed"))

        elif errmsg in ("expired", "server"):
            self.retry(wait=600, msg=errmsg)

        elif errmsg == "full":
            self.fail(self._("Server is full"))

        elif 'slot' in errmsg:
            self.wait(3600, reconnect=True)
            self.restart(errmsg)

        else:
            self.wait(60, reconnect=True)
            self.restart(errmsg)

    def challenge(self, key=None, data=None, version=None, secure_token=None):
        key = key or self.retrieve_key(data)
        secure_token = secure_token or self.detect_secure_token(
            data) if version == 2 else None

        if version in (1, 2):
            return getattr(self, "_challenge_v%s" % version)(key, secure_token)

        else:
            return self.challenge(key,
                                  data,
                                  version=self.detect_version(data=data),
                                  secure_token=secure_token)

    def detect_version(self, data=None):
        data = data or self.retrieve_data()

        v1 = re.search(self.KEY_V1_PATTERN, data) is not None
        v2 = re.search(self.KEY_V2_PATTERN, data) is not None

        if v1 is True and v2 is False:
            self.pyload.log.debug("Detected Recaptcha v1")
            return 1

        elif v1 is False and v2 is True:
            self.pyload.log.debug("Detected Recaptcha v2")
            return 2

        else:
            self.pyload.log.warning(self._("Could not properly detect ReCaptcha version, defaulting to v1"))
            return 1

    def retrieve_data(self):
        return self.file.plugin.data or self.file.plugin.last_html or ""

    #: Currently secure_token is supported in ReCaptcha v2 only
    def _challenge_v1(self, key, secure_token):
        html = to_str(self.file.plugin.load("http://www.google.com/recaptcha/api/challenge",
                                       get={'k': key}))
        try:
            challenge = re.search("challenge : '(.+?)',", html).group(1)
            server = re.search("server : '(.+?)',", html).group(1)

        except (AttributeError, IndexError):
            self.fail(self._("ReCaptcha challenge pattern not found"))

        self.pyload.log.debug("Challenge: %s" % challenge)

        return self.result(server, challenge, key)

    def result(self, server, challenge, key):
        #TODO: is the next statement required?
        self.file.plugin.load(
            "http://www.google.com/recaptcha/api/js/recaptcha.js")
        html = to_str(self.file.plugin.load("http://www.google.com/recaptcha/api/reload",
                                       get={'c': challenge,
                                            'k': key,
                                            'reason': "i",
                                            'type': "image"}))

        try:
            challenge = re.search('\(\'(.+?)\',', html).group(1)

        except (AttributeError, IndexError):
            self.fail(self._("ReCaptcha second challenge pattern not found"))

        self.pyload.log.debug("Second challenge: %s" % challenge)
        result = self.decrypt(urllib.parse.urljoin(server, "image"),
                              get={'c': challenge},
                              cookies=True,
                              input_type="jpg")

        return result, challenge

    def decrypt(self, url, get={}, post={}, ref=False, cookies=True, req=None,
                input_type='jpg', output_type='textual', timeout=120):
        img = self.load(
            url,
            get=get,
            post=post,
            ref=ref,
            cookies=cookies,
            decode=False)#,
            #req=req or self.file.plugin.req)

        time_ref = ('%.2f' % time.time())[-6:].replace('.', '')
        with open(os.path.join(r'C:\DATA\PyCharmProject\pyload_folders\temp', 'captcha_image_%s_%s.%s' % (self.file.plugin.__name__, time_ref, input_type)), 'wb') as img_f:
            img_f.write(img)

        result = 'calle calle'

        print('Use debugger to stop here.')

        os.remove(img_f.name)
        return result

    def decrypt_image(self, img, input_type='jpg',
                      output_type='textual', timeout=120):
        """
        Loads a captcha and decrypts it with ocr, plugin, user input

        :param img: image raw data
        :param get: get part for request
        :param post: post part for request
        :param cookies: True if cookies should be enabled
        :param input_type: Type of the Image
        :param output_type: 'textual' if text is written on the captcha\
        or 'positional' for captcha where the user have to click\
        on a specific region on the captcha

        :return: result of decrypting
        """
        result = None
        time_ref = ("%.2f" % time.time())[-6:].replace(".", "")

        with open(os.path.join("tmp", "captcha_image_%s_%s.%s" % (self.file.plugin.__name__, time_ref, input_type)), "wb") as img_f:
            img_f.write(img)

        if not result:
            captchaManager = self.pyload.captchaManager

            try:
                self.task = captchaManager.newTask(
                    img, input_type, img_f.name, output_type, self._continue)

                captchaManager.handleCaptcha(self.task)

                self._continue

                # # @TODO: Move to `CaptchaManager` in 0.4.10
                # self.task.setWaiting(max(timeout, 50))
                # while self.task.isWaiting():
                #     self.file.plugin.check_status()
                #     time.sleep(1)

            finally:
                captchaManager.removeTask(self.task)

            result = self.task.result

            if self.task.error:
                if not self.task.handler and not self.pyload.isClientConnected():
                    self.pyload.log.warning(
                        self._("No Client connected for captcha decrypting"))
                    self.fail(self._("No Client connected for captcha decrypting"))
                else:
                    self.file.plugin.retry_captcha(msg=self.task.error)

            elif self.task.result:
                self.pyload.log.info(self._("Captcha result: `%s`") % (result,))

            else:
                self.file.plugin.retry_captcha(
                    msg=self._("No captcha result obtained in appropriate timing"))

        if not self.pyload.debug:
            self.remove(img_f.name, trash=False)

        return result