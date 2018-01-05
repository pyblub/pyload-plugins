from pyload.core.network.hoster import Hoster

class Html(Hoster):
    __name__ = 'Html'
    __version__ = '0.1'

    def process(self, file):
        """The 'main' method of every plugin, you **have to** overwrite it."""
        self.download(file.url)

        return
