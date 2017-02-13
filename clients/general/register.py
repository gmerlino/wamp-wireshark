from twisted.internet.defer import inlineCallbacks
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner

class MyComponent(ApplicationSession):

    @inlineCallbacks
    def onJoin(self, details):
        print("session joined")
        # can do subscribes, registers here e.g.:
        # yield self.subscribe(...)
        # yield self.register(...)

        def add2(x, y):
            return x + y

        try:
            yield self.register(add2, u'com.myapp.add2')
            print("procedure registered")
            
        except Exception as e:
            print("could not register procedure: {0}".format(e))
        
    def __init__(self, config=None):
        ApplicationSession.__init__(self, config)
        print("component created")

    def onConnect(self):
        print("transport connected")
        self.join(self.config.realm)

    def onChallenge(self, challenge):
        print("authentication challenge received")

    def onLeave(self, details):
        print("session left")

    def onDisconnect(self):
        print("transport disconnected")

if __name__ == '__main__':
    runner = ApplicationRunner(url=u"ws://localhost:8080/ws", realm=u"realm1")
    runner.run(MyComponent)
