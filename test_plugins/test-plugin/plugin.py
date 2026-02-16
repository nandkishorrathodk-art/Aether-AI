
def hello():
    return "Hello from test plugin!"

class TestPlugin:
    def __init__(self):
        self.name = "test-plugin"
    
    def execute(self, command):
        if command == "hello":
            return hello()
        return None

def create_plugin():
    return TestPlugin()
