import lief
from model import file_model
from engine_meta import engine_meta


def main() -> None:
    TARGET_FILE = "C:\\Users\\andrea.cozzi\\Desktop\\main.exe"
    model : file_model.FileModel = file_model.FileModel(TARGET_FILE)
    engine: engine_meta.MetamorphicEngine = engine_meta.MetamorphicEngine(model)
    """
    _ = engine.create_graph_cfg(
        section=".text",
        save_ass_out="output.txt",
        save_cfg_out="out.json"
    )
    """
    CODE = b"\xb8\x45\x23\x01\x00\x31\xdb\x83\xc1\x0a\x89\xf7\x90"
    engine.test_indipendent_istruction(CODE)


if __name__ == "__main__":
    main()

