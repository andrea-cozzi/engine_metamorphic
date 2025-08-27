from app.app import Application
from constant_var import PATH_EXE


if __name__ == "__main__":
    app = Application(executable_path=PATH_EXE)
    app.run()
